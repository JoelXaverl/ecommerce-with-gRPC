package handler

import (
	"context"
	"fmt"

	"github.com/JoelXaverl/ecommerce-go-grpc-be/internal/utils"
	"github.com/JoelXaverl/ecommerce-go-grpc-be/pb/service"
)

type serviceHandler struct {
	service.UnimplementedHelloWorldServiceServer
}

func (sh *serviceHandler) HelloWorld(ctx context.Context, request *service.HelloWorldRequest) (*service.HelloWorldResponse, error) {
	validationerrors, err := utils.CheckValidation(request)
	if err != nil {
		return nil, err
	}
	if validationerrors != nil {
		return &service.HelloWorldResponse{ 
			Base: utils.ValidationErrorResponse(validationerrors),
		}, nil
	}
	
	return &service.HelloWorldResponse{
		Message: fmt.Sprintf("Hello %s", request.Name),
		Base: utils.SuccessResponse("Success"),
	}, nil
}

func NewServiceHandler() *serviceHandler {
	return &serviceHandler{}
}