# Use an official lightweight Go image
FROM golang:1.23-alpine

# Set working directory in the container
WORKDIR /app

# Copy go mod and sum files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy the entire project
COPY . .

# Build the Go application
RUN go build -o /app/main .

# Expose the application port (change if needed)
EXPOSE 8080

# Run the application
CMD ["/app/main"]
