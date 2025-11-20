package storage

import (
	"context"
	"errors"
	"iter"
)

var ErrUserAlreadyExists = errors.New("user already exists")

type User struct {
	Id        string `json:"id,omitempty"`
	Name      string `json:"name,omitempty"`
	Email     string `json:"email,omitempty"`
	Tags      string `json:"tags,omitempty"`
	Superuser bool   `json:"superuser,omitempty"`
}

type ListFilter struct {
	Prefix string
}

type UserService interface {
	GetUsers(ctx context.Context, id ...string) ([]*User, error)
	GetUserByName(ctx context.Context, name string) (*User, error)
	PutUser(ctx context.Context, user *User, delete bool) (*User, error)
	ListUsers(ctx context.Context, prefix string) (iter.Seq[*User], error)
}
