package model

import "time"

type User struct {
	Id        string
	Username  string
	Superuser bool
	Tags      map[string]string
}

type AccountPermission struct {
	Id             string
	AccountId      string
	PermissionType string
	ObjectId       string
}

type RolePermission struct {
	Id     string
	RoleId string
}

type Account struct {
	Id      string
	Name    string
	AwsId   int
	Enabled bool
	Tags    map[string]string
}

type Role struct {
	Id                 string
	AccountId          string
	Rolename           string
	ManagedPolicies    []string
	MaxSessionDuration time.Duration
	Enabled            bool
	Tags               map[string]string
}
type InlinePolicy struct {
	Id       string
	RoleId   string
	Name     string
	Document string
}
