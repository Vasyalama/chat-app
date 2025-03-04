-- Insert mock users
INSERT INTO users (username, first_name, last_name, email, password_hash, bio, verified, created_at) VALUES
(NULL, 'John', 'Doe', 'john.doe@example.com', 'hashedpassword123', 'I am John Doe.', 1, NOW()),
('jane_doe', 'Jane', 'Doe', 'jane.doe@example.com', 'hashedpassword456', 'I love coding!', 1, NOW());
