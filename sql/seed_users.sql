-- Insert mock users
INSERT INTO users (username, first_name, last_name, email, password_hash, bio, verified, created_at) VALUES
(NULL, 'John', 'Doe', 'john.doe@example.com', 'hashedpassword123', 'I am John Doe.', 1, NOW()),
('jane_doe', 'Jane', 'Doe', 'jane.doe@example.com', 'hashedpassword456', 'I love coding!', 1, NOW()),
('vasya_pupkin', 'Vasya', 'Pupkin', 'vasyapupkin@gmail.com', 'pAOnfOAIwsrNOYwuXEr0bA==$+IS8LZiI8D1/sY9WS9m1eFAdQTFu68WuGb9FYlb2S3g=', 'i am vasya pupkin', 1, NOW());
