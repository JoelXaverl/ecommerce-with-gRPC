package utils

import (
	"github.com/JoelXaverl/ecommerce-go-grpc-be/pb/common"
)

func SuccessResponse(message string) *common.BaseResponse {
	return &common.BaseResponse{
		StatusCode: 200,
		Message: message,
	}
}