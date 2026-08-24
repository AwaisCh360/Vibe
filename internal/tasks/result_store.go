package tasks

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"armur-codescanner/internal/redis"
)

func SaveTaskResult(taskID string, result map[string]any) error {
	ctx := context.Background()

	resultData, err := json.Marshal(result)
	if err != nil {
		return err
	}

	return redis.RedisClient().Set(ctx, taskID, resultData, 24*time.Hour).Err()
}

func GetTaskResult(taskID string) (any, error) {
	ctx := context.Background()

	resultData, err := redis.RedisClient().Get(ctx, taskID).Result()
	if err != nil {
		if err.Error() == "redis: nil" {
			return nil, errors.New("task result not found")
		}
		return nil, err
	}

	var result interface{}
	if err := json.Unmarshal([]byte(resultData), &result); err != nil {
		return nil, err
	}
	return result, nil
}
