// Package s21 wraps the small slice of the s21auto-client-go library the
// identity service needs: authenticate a (login, password) pair and resolve
// the resulting profile.
package s21

import (
	"context"
	"errors"
	"strings"

	s21client "github.com/arseniisemenow/s21auto-client-go"
	"github.com/arseniisemenow/s21auto-client-go/requests"
)

// Profile is the subset of S21 user data the service stores.
type Profile struct {
	Login         string
	CampusID      string
	CampusName    string
	CoalitionName string
}

// Client is the abstraction over s21auto-client-go used by the service. It is
// also implemented by the test mock at mock.go.
type Client interface {
	// Authenticate validates (login, password) and returns the resulting
	// profile, or ErrInvalidCredentials on bad creds.
	Authenticate(ctx context.Context, login, password string) (Profile, error)

	// LookupByLogin resolves an arbitrary S21 login to a profile using the
	// admin's own credentials. Returns ErrNotFound if no such login exists,
	// ErrInvalidCredentials if the supplied admin creds were rejected.
	LookupByLogin(ctx context.Context, adminLogin, adminPassword, targetLogin string) (Profile, error)
}

// Errors returned by S21 implementations.
var (
	ErrInvalidCredentials = errors.New("s21: invalid credentials")
	ErrNotFound           = errors.New("s21: not found")
	ErrUnavailable        = errors.New("s21: unavailable")
)

// realClient talks to platform.21-school.ru via s21auto-client-go.
type realClient struct{}

// NewClient returns the production Client.
func NewClient() Client { return realClient{} }

func (realClient) Authenticate(_ context.Context, login, password string) (Profile, error) {
	c := s21client.New(s21client.DefaultAuth(login, password))
	data, err := c.R().DashboardHeaderGetInfo(requests.DashboardHeaderGetInfo_Variables{})
	if err != nil {
		return Profile{}, mapAuthError(err)
	}
	return profileFromDashboardData(data)
}

func (realClient) LookupByLogin(_ context.Context, adminLogin, adminPassword, targetLogin string) (Profile, error) {
	c := s21client.New(s21client.DefaultAuth(adminLogin, adminPassword))
	// Validate the admin's creds first by hitting the dashboard endpoint.
	adminData, err := c.R().DashboardHeaderGetInfo(requests.DashboardHeaderGetInfo_Variables{})
	if err != nil {
		return Profile{}, mapAuthError(err)
	}
	// Resolve target.
	res, err := c.R().PublicProfileGetCredentialsByLogin(requests.PublicProfileGetCredentialsByLogin_Variables{
		Login: targetLogin,
	})
	if err != nil {
		return Profile{}, err
	}
	student := res.School21.GetStudentByLogin
	if student.StudentID == "" {
		return Profile{}, ErrNotFound
	}
	// PublicProfileGetCredentialsByLogin doesn't return campus directly. As a
	// reasonable default, attribute the target user to the admin's campus.
	adminProfile, err := profileFromDashboardData(adminData)
	if err != nil {
		return Profile{}, err
	}
	return Profile{
		Login:         targetLogin,
		CampusID:      adminProfile.CampusID,
		CampusName:    adminProfile.CampusName,
		CoalitionName: "",
	}, nil
}

func profileFromDashboardData(data requests.DashboardHeaderGetInfo_Data) (Profile, error) {
	user := data.User.GetCurrentUser
	if user.Login == "" {
		return Profile{}, ErrInvalidCredentials
	}
	var campusID, campusName string
	if len(user.StudentRoles) > 0 {
		campusID = user.StudentRoles[0].School.ID
		campusName = user.StudentRoles[0].School.ShortName
	}
	coalition := data.Student.GetUserTournamentWidget.CoalitionMember.Coalition.Name
	return Profile{
		Login:         user.Login,
		CampusID:      campusID,
		CampusName:    campusName,
		CoalitionName: coalition,
	}, nil
}

func mapAuthError(err error) error {
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "unauthorized"),
		strings.Contains(msg, "authentication failed"),
		strings.Contains(msg, "401"),
		strings.Contains(msg, "invalid"):
		return errors.Join(ErrInvalidCredentials, err)
	}
	return errors.Join(ErrUnavailable, err)
}
