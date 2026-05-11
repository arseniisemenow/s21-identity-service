// Package api holds the HTTP handlers and request/response models for the
// identity service.
package api

import "time"

// User is the wire shape returned by the service. Identical to
// identityclient.User (kept duplicated so the service doesn't depend on the
// SDK).
type User struct {
	TelegramID    int64     `json:"telegram_id"`
	Nickname      string    `json:"nickname"`
	CampusID      string    `json:"campus_id"`
	CampusName    string    `json:"campus_name"`
	CoalitionName string    `json:"coalition_name"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

// LookupTelegramBatchRequest is the POST body for the batch endpoint.
type LookupTelegramBatchRequest struct {
	TelegramIDs []int64 `json:"telegram_ids"`
}

// LookupTelegramBatchResponse is what batch returns.
type LookupTelegramBatchResponse struct {
	Users []User `json:"users"`
}

// PutUserRequest is the PUT body.
type PutUserRequest struct {
	Nickname string `json:"nickname"`
}

// ListResponse is the array wrapper for nickname lookups.
type ListResponse struct {
	Users []User `json:"users"`
}

// ErrorBody is the standard error envelope.
type ErrorBody struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}
