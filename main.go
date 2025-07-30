package main

import (
	"context"
	"log"
	"net"
	"os"

	"github.com/JoelXaverl/ecommerce-go-grpc-be/internal/handler"
	"github.com/JoelXaverl/ecommerce-go-grpc-be/pb/service"
	"github.com/JoelXaverl/ecommerce-go-grpc-be/pkg/database"
	"github.com/JoelXaverl/ecommerce-go-grpc-be/pkg/grpcmiddleware"
	"github.com/joho/godotenv"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

func main() {
	ctx := context.Background()
	godotenv.Load()
	lis, err := net.Listen("tcp", ":50052")
	if err != nil {
		log.Panicf("Error whe listening %v", err)
	}

	database.ConnectDB(ctx, os.Getenv("DB_URI"))
	log.Println("Connected to database")

	serviceHadler := handler.NewServiceHandler()

	serv := grpc.NewServer(
		grpc.ChainUnaryInterceptor(
			grpcmiddleware.ErrorMiddleware,
		),
	)

	service.RegisterHelloWorldServiceServer(serv, serviceHadler)

	if os.Getenv("ENVIRONMENT") == "dev" {
		reflection.Register(serv)
		log.Println("Reflection is registered.")
	}

	log.Println("Server is running on :50052 port")
	if err := serv.Serve(lis); err != nil {
		log.Panicf("Server is error %v", err)
	}
}