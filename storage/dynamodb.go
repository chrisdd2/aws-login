package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

type DynamoDBStorage struct {
	client    *dynamodb.Client
	tableName string
}

func NewDynamoDBStorage(client *dynamodb.Client, tableName string) (*DynamoDBStorage, error) {
	return &DynamoDBStorage{
		client:    client,
		tableName: tableName,
	}, nil
}

// EnsureSchema creates the DynamoDB table if it doesn't exist
func (s *DynamoDBStorage) EnsureSchema(ctx context.Context) error {
	// Check if table exists
	_, err := s.client.DescribeTable(ctx, &dynamodb.DescribeTableInput{
		TableName: aws.String(s.tableName),
	})
	if err == nil {
		return nil // Table exists
	}

	// Create table
	_, err = s.client.CreateTable(ctx, &dynamodb.CreateTableInput{
		TableName: aws.String(s.tableName),
		AttributeDefinitions: []types.AttributeDefinition{
			{
				AttributeName: aws.String("PK"),
				AttributeType: types.ScalarAttributeTypeS,
			},
			{
				AttributeName: aws.String("SK"),
				AttributeType: types.ScalarAttributeTypeS,
			},
			{
				AttributeName: aws.String("GSI1PK"),
				AttributeType: types.ScalarAttributeTypeS,
			},
			{
				AttributeName: aws.String("GSI1SK"),
				AttributeType: types.ScalarAttributeTypeS,
			},
		},
		KeySchema: []types.KeySchemaElement{
			{
				AttributeName: aws.String("PK"),
				KeyType:       types.KeyTypeHash,
			},
			{
				AttributeName: aws.String("SK"),
				KeyType:       types.KeyTypeRange,
			},
		},
		GlobalSecondaryIndexes: []types.GlobalSecondaryIndex{
			{
				IndexName: aws.String("GSI1"),
				KeySchema: []types.KeySchemaElement{
					{
						AttributeName: aws.String("GSI1PK"),
						KeyType:       types.KeyTypeHash,
					},
					{
						AttributeName: aws.String("GSI1SK"),
						KeyType:       types.KeyTypeRange,
					},
				},
				Projection: &types.Projection{
					ProjectionType: types.ProjectionTypeAll,
				},
				ProvisionedThroughput: &types.ProvisionedThroughput{
					ReadCapacityUnits:  aws.Int64(5),
					WriteCapacityUnits: aws.Int64(5),
				},
			},
		},
		ProvisionedThroughput: &types.ProvisionedThroughput{
			ReadCapacityUnits:  aws.Int64(5),
			WriteCapacityUnits: aws.Int64(5),
		},
	})
	return err
}

// Helper functions for DynamoDB key generation
func userPK(userId string) string {
	return fmt.Sprintf("USER#%s", userId)
}

func userSK() string {
	return "METADATA"
}

func userByUsernamePK(username string) string {
	return fmt.Sprintf("USERNAME#%s", username)
}

func accountPK(accountId string) string {
	return fmt.Sprintf("ACCOUNT#%s", accountId)
}

func accountSK() string {
	return "METADATA"
}

func accountByAwsIdPK(awsAccountId int) string {
	return fmt.Sprintf("AWSACCOUNT#%d", awsAccountId)
}

func permissionPK(userId, accountId string) string {
	return fmt.Sprintf("PERM#%s#%s", userId, accountId)
}

func permissionSK(permType, scope string) string {
	return fmt.Sprintf("%s#%s", permType, scope)
}

// ListUsers implements the Storage interface
func (s *DynamoDBStorage) ListUsers(ctx context.Context, filter string, startToken *string) (ListUserResult, error) {
	// Use GSI1 to scan users
	params := &dynamodb.QueryInput{
		TableName:              aws.String(s.tableName),
		IndexName:              aws.String("GSI1"),
		KeyConditionExpression: aws.String("GSI1PK begins_with :pk"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":pk": &types.AttributeValueMemberS{Value: "USER#"},
		},
		Limit: aws.Int32(ListResultPageSize),
	}

	if startToken != nil {
		params.ExclusiveStartKey = map[string]types.AttributeValue{
			"GSI1PK": &types.AttributeValueMemberS{Value: "USER#"},
			"GSI1SK": &types.AttributeValueMemberS{Value: *startToken},
		}
	}

	result, err := s.client.Query(ctx, params)
	if err != nil {
		return ListUserResult{}, err
	}

	users := make([]User, 0, len(result.Items))
	for _, item := range result.Items {
		var user User
		err = attributevalue.UnmarshalMap(item, &user)
		if err != nil {
			return ListUserResult{}, err
		}
		if filter == "" || strings.HasPrefix(user.Username, filter) {
			users = append(users, user)
		}
	}

	var nextToken *string
	if result.LastEvaluatedKey != nil {
		if sk, ok := result.LastEvaluatedKey["GSI1SK"].(*types.AttributeValueMemberS); ok {
			nextToken = &sk.Value
		}
	}

	return ListUserResult{Users: users, StartToken: nextToken}, nil
}

// GetUserByUsername implements the Storage interface
func (s *DynamoDBStorage) GetUserByUsername(ctx context.Context, username string) (User, error) {
	if username == "" {
		return User{}, ErrUserNotFound
	}

	result, err := s.client.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(s.tableName),
		Key: map[string]types.AttributeValue{
			"PK": &types.AttributeValueMemberS{Value: userByUsernamePK(username)},
			"SK": &types.AttributeValueMemberS{Value: "METADATA"},
		},
	})
	if err != nil {
		return User{}, err
	}
	if result.Item == nil {
		return User{}, ErrUserNotFound
	}

	var user User
	err = attributevalue.UnmarshalMap(result.Item, &user)
	return user, err
}

// GetUserById implements the Storage interface
func (s *DynamoDBStorage) GetUserById(ctx context.Context, userId string) (User, error) {
	if userId == "" {
		return User{}, ErrUserNotFound
	}

	result, err := s.client.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(s.tableName),
		Key: map[string]types.AttributeValue{
			"PK": &types.AttributeValueMemberS{Value: userPK(userId)},
			"SK": &types.AttributeValueMemberS{Value: userSK()},
		},
	})
	if err != nil {
		return User{}, err
	}
	if result.Item == nil {
		return User{}, ErrUserNotFound
	}

	var user User
	err = attributevalue.UnmarshalMap(result.Item, &user)
	return user, err
}

// BatchGetUserById implements the Storage interface
func (s *DynamoDBStorage) BatchGetUserById(ctx context.Context, userIds ...string) ([]User, error) {
	if len(userIds) == 0 {
		return []User{}, nil
	}

	keys := make([]map[string]types.AttributeValue, len(userIds))
	for i, id := range userIds {
		keys[i] = map[string]types.AttributeValue{
			"PK": &types.AttributeValueMemberS{Value: userPK(id)},
			"SK": &types.AttributeValueMemberS{Value: userSK()},
		}
	}

	result, err := s.client.BatchGetItem(ctx, &dynamodb.BatchGetItemInput{
		RequestItems: map[string]types.KeysAndAttributes{
			s.tableName: {
				Keys: keys,
			},
		},
	})
	if err != nil {
		return nil, err
	}

	users := make([]User, 0, len(result.Responses[s.tableName]))
	for _, item := range result.Responses[s.tableName] {
		var user User
		err = attributevalue.UnmarshalMap(item, &user)
		if err != nil {
			return nil, err
		}
		users = append(users, user)
	}

	return users, nil
}

// PutUser implements the Storage interface
func (s *DynamoDBStorage) PutUser(ctx context.Context, user User, delete bool) (User, error) {
	if delete {
		_, err := s.client.DeleteItem(ctx, &dynamodb.DeleteItemInput{
			TableName: aws.String(s.tableName),
			Key: map[string]types.AttributeValue{
				"PK": &types.AttributeValueMemberS{Value: userPK(user.Id)},
				"SK": &types.AttributeValueMemberS{Value: userSK()},
			},
		})
		return user, err
	}

	if user.Id == "" {
		user.Id = newUuid()
	}

	// Create both the main user record and the username index
	items := []types.TransactWriteItem{
		{
			Put: &types.Put{
				TableName: aws.String(s.tableName),
				Item: map[string]types.AttributeValue{
					"PK":        &types.AttributeValueMemberS{Value: userPK(user.Id)},
					"SK":        &types.AttributeValueMemberS{Value: userSK()},
					"GSI1PK":    &types.AttributeValueMemberS{Value: userPK(user.Id)},
					"GSI1SK":    &types.AttributeValueMemberS{Value: userSK()},
					"Id":        &types.AttributeValueMemberS{Value: user.Id},
					"Username":  &types.AttributeValueMemberS{Value: user.Username},
					"Email":     &types.AttributeValueMemberS{Value: user.Email},
					"Tags":      &types.AttributeValueMemberS{Value: user.Tags},
					"Superuser": &types.AttributeValueMemberBOOL{Value: user.Superuser},
				},
			},
		},
		{
			Put: &types.Put{
				TableName: aws.String(s.tableName),
				Item: map[string]types.AttributeValue{
					"PK":     &types.AttributeValueMemberS{Value: userByUsernamePK(user.Username)},
					"SK":     &types.AttributeValueMemberS{Value: "METADATA"},
					"UserId": &types.AttributeValueMemberS{Value: user.Id},
				},
			},
		},
	}

	_, err := s.client.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{
		TransactItems: items,
	})
	return user, err
}

// ListAccounts implements the Storage interface
func (s *DynamoDBStorage) ListAccounts(ctx context.Context, startToken *string) (ListAccountResult, error) {

	params := &dynamodb.QueryInput{
		TableName:              aws.String(s.tableName),
		IndexName:              aws.String("GSI1"),
		KeyConditionExpression: aws.String("GSI1PK begins_with :pk"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":pk": &types.AttributeValueMemberS{Value: "ACCOUNT#"},
		},
		Limit: aws.Int32(ListResultPageSize),
	}

	if startToken != nil {
		params.ExclusiveStartKey = map[string]types.AttributeValue{
			"GSI1PK": &types.AttributeValueMemberS{Value: "ACCOUNT#"},
			"GSI1SK": &types.AttributeValueMemberS{Value: *startToken},
		}
	}

	result, err := s.client.Query(ctx, params)
	if err != nil {
		return ListAccountResult{}, err
	}

	accounts := make([]Account, 0, len(result.Items))
	for _, item := range result.Items {
		var account Account
		err = attributevalue.UnmarshalMap(item, &account)
		if err != nil {
			return ListAccountResult{}, err
		}
		accounts = append(accounts, account)
	}

	var nextToken *string
	if result.LastEvaluatedKey != nil {
		if sk, ok := result.LastEvaluatedKey["GSI1SK"].(*types.AttributeValueMemberS); ok {
			nextToken = &sk.Value
		}
	}

	return ListAccountResult{Accounts: accounts, StartToken: nextToken}, nil
}

// GetAccountById implements the Storage interface
func (s *DynamoDBStorage) GetAccountById(ctx context.Context, accountId string) (Account, error) {
	if accountId == "" {
		return Account{}, ErrAccountNotFound
	}

	result, err := s.client.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(s.tableName),
		Key: map[string]types.AttributeValue{
			"PK": &types.AttributeValueMemberS{Value: accountPK(accountId)},
			"SK": &types.AttributeValueMemberS{Value: accountSK()},
		},
	})
	if err != nil {
		return Account{}, err
	}
	if result.Item == nil {
		return Account{}, ErrAccountNotFound
	}

	var account Account
	err = attributevalue.UnmarshalMap(result.Item, &account)
	return account, err
}

// GetAccountByAwsAccountId implements the Storage interface
func (s *DynamoDBStorage) GetAccountByAwsAccountId(ctx context.Context, awsAccountId int) (Account, error) {
	if awsAccountId == 0 {
		return Account{}, ErrAccountNotFound
	}

	result, err := s.client.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(s.tableName),
		Key: map[string]types.AttributeValue{
			"PK": &types.AttributeValueMemberS{Value: accountByAwsIdPK(awsAccountId)},
			"SK": &types.AttributeValueMemberS{Value: "METADATA"},
		},
	})
	if err != nil {
		return Account{}, err
	}
	if result.Item == nil {
		return Account{}, ErrAccountNotFound
	}

	var account Account
	err = attributevalue.UnmarshalMap(result.Item, &account)
	return account, err
}

// PutAccount implements the Storage interface
func (s *DynamoDBStorage) PutAccount(ctx context.Context, account Account, delete bool) (Account, error) {
	if delete {
		_, err := s.client.DeleteItem(ctx, &dynamodb.DeleteItemInput{
			TableName: aws.String(s.tableName),
			Key: map[string]types.AttributeValue{
				"PK": &types.AttributeValueMemberS{Value: accountPK(account.Id)},
				"SK": &types.AttributeValueMemberS{Value: accountSK()},
			},
		})
		return account, err
	}

	if account.Id == "" {
		account.Id = newUuid()
	}

	// Create both the main account record and the AWS account ID index
	items := []types.TransactWriteItem{
		{
			Put: &types.Put{
				TableName: aws.String(s.tableName),
				Item: map[string]types.AttributeValue{
					"PK":           &types.AttributeValueMemberS{Value: accountPK(account.Id)},
					"SK":           &types.AttributeValueMemberS{Value: accountSK()},
					"GSI1PK":       &types.AttributeValueMemberS{Value: accountPK(account.Id)},
					"GSI1SK":       &types.AttributeValueMemberS{Value: accountSK()},
					"Id":           &types.AttributeValueMemberS{Value: account.Id},
					"AwsAccountId": &types.AttributeValueMemberN{Value: strconv.Itoa(account.AwsAccountId)},
					"FriendlyName": &types.AttributeValueMemberS{Value: account.FriendlyName},
					"Enabled":      &types.AttributeValueMemberBOOL{Value: account.Enabled},
					"Tags":         &types.AttributeValueMemberS{Value: serializeTags(account.Tags)},
				},
			},
		},
		{
			Put: &types.Put{
				TableName: aws.String(s.tableName),
				Item: map[string]types.AttributeValue{
					"PK":        &types.AttributeValueMemberS{Value: accountByAwsIdPK(account.AwsAccountId)},
					"SK":        &types.AttributeValueMemberS{Value: "METADATA"},
					"AccountId": &types.AttributeValueMemberS{Value: account.Id},
				},
			},
		},
	}

	_, err := s.client.TransactWriteItems(ctx, &dynamodb.TransactWriteItemsInput{
		TransactItems: items,
	})
	return account, err
}

// ListPermissions implements the Storage interface
func (s *DynamoDBStorage) ListPermissions(ctx context.Context, userId string, accountId string, permissionType string, scope string, startToken *string) (ListPermissionResult, error) {

	keyCondition := "PK begins_with :pk"
	exprValues := map[string]types.AttributeValue{
		":pk": &types.AttributeValueMemberS{Value: permissionPK(userId, accountId)},
	}

	if permissionType != "" {
		keyCondition += " AND begins_with(SK, :sk)"
		exprValues[":sk"] = &types.AttributeValueMemberS{Value: permissionType}
	}

	params := &dynamodb.QueryInput{
		TableName:                 aws.String(s.tableName),
		KeyConditionExpression:    aws.String(keyCondition),
		ExpressionAttributeValues: exprValues,
		Limit:                     aws.Int32(ListResultPageSize),
	}

	if startToken != nil {
		params.ExclusiveStartKey = map[string]types.AttributeValue{
			"PK": &types.AttributeValueMemberS{Value: permissionPK(userId, accountId)},
			"SK": &types.AttributeValueMemberS{Value: *startToken},
		}
	}

	result, err := s.client.Query(ctx, params)
	if err != nil {
		return ListPermissionResult{}, err
	}

	permissions := make([]Permission, 0, len(result.Items))
	for _, item := range result.Items {
		var perm Permission
		err = attributevalue.UnmarshalMap(item, &perm)
		if err != nil {
			return ListPermissionResult{}, err
		}
		if scope == "" || perm.Scope == scope {
			permissions = append(permissions, perm)
		}
	}

	var nextToken *string
	if result.LastEvaluatedKey != nil {
		if sk, ok := result.LastEvaluatedKey["SK"].(*types.AttributeValueMemberS); ok {
			nextToken = &sk.Value
		}
	}

	return ListPermissionResult{Permissions: permissions, StartToken: nextToken}, nil
}

// PutRolePermission implements the Storage interface
func (s *DynamoDBStorage) PutRolePermission(ctx context.Context, perm Permission, delete bool) error {
	if delete {
		_, err := s.client.DeleteItem(ctx, &dynamodb.DeleteItemInput{
			TableName: aws.String(s.tableName),
			Key: map[string]types.AttributeValue{
				"PK": &types.AttributeValueMemberS{Value: permissionPK(perm.UserId, perm.AccountId)},
				"SK": &types.AttributeValueMemberS{Value: permissionSK(perm.Type, perm.Scope)},
			},
		})
		return err
	}

	valueStr, err := json.Marshal(perm.Value)
	if err != nil {
		return err
	}

	_, err = s.client.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: aws.String(s.tableName),
		Item: map[string]types.AttributeValue{
			"PK":        &types.AttributeValueMemberS{Value: permissionPK(perm.UserId, perm.AccountId)},
			"SK":        &types.AttributeValueMemberS{Value: permissionSK(perm.Type, perm.Scope)},
			"UserId":    &types.AttributeValueMemberS{Value: perm.UserId},
			"AccountId": &types.AttributeValueMemberS{Value: perm.AccountId},
			"Type":      &types.AttributeValueMemberS{Value: perm.Type},
			"Scope":     &types.AttributeValueMemberS{Value: perm.Scope},
			"Value":     &types.AttributeValueMemberS{Value: string(valueStr)},
		},
	})
	return err
}

// ListAccountsForUser implements the Storage interface
func (s *DynamoDBStorage) ListAccountsForUser(ctx context.Context, userId string, startToken *string) (ListAccountResult, error) {
	startIdx, err := parseStartToken(startToken)
	if err != nil {
		return ListAccountResult{}, err
	}

	// First get all permissions for the user
	permParams := &dynamodb.QueryInput{
		TableName:              aws.String(s.tableName),
		KeyConditionExpression: aws.String("PK begins_with :pk"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":pk": &types.AttributeValueMemberS{Value: permissionPK(userId, "")},
		},
	}

	permResult, err := s.client.Query(ctx, permParams)
	if err != nil {
		return ListAccountResult{}, err
	}

	// Extract unique account IDs
	accountIds := make(map[string]struct{})
	for _, item := range permResult.Items {
		if accountId, ok := item["AccountId"].(*types.AttributeValueMemberS); ok {
			accountIds[accountId.Value] = struct{}{}
		}
	}

	// Get accounts for each account ID
	accounts := make([]Account, 0, len(accountIds))
	for accountId := range accountIds {
		account, err := s.GetAccountById(ctx, accountId)
		if err != nil {
			continue // Skip accounts that can't be found
		}
		accounts = append(accounts, account)
	}

	// Apply pagination
	start := startIdx
	end := start + ListResultPageSize
	if end > len(accounts) {
		end = len(accounts)
	}

	var nextToken *string
	if end < len(accounts) {
		nextToken = generateStartToken(end)
	}

	return ListAccountResult{
		Accounts:   accounts[start:end],
		StartToken: nextToken,
	}, nil
}
