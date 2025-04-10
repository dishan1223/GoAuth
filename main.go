package main

import (
    "log"
    "time"
    "github.com/gofiber/fiber/v2"
    "gorm.io/gorm"
    "gorm.io/driver/sqlite"
    "golang.org/x/crypto/bcrypt"
    "github.com/golang-jwt/jwt/v5"
)

// TODO: Add protected Routes

// globals (shift these to .env for prod)
var jwtSecret = []byte("superSecret")

var DB *gorm.DB


// Struct
type User struct {
    gorm.Model
    Username string `json:"username"`
    Email    string `json:"email"`
    Password string `json:"password"`
}

// API routes
func GetUsers(c *fiber.Ctx) error {
    var users []User
    DB.Find(&users)

    if len(users) == 0 {
        return c.SendString("No users found\n")
    }
    return c.JSON(users)
}

func Login(c *fiber.Ctx) error {
    type loginRequest struct {
        Username string `json:"username"`
        Password string `json:"password"`
    }


    var input loginRequest
    if err := c.BodyParser(&input); err != nil{
        return c.Status(400).SendString("Invalid request\n")
    }
    
    // find user by username
    var user User
    if err := DB.Where("username = ?", input.Username).First(&user).Error; err != nil{
        return c.Status(fiber.StatusUnauthorized).SendString("Invalid username or password\n")
    }


    // compare hashed password 
    if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(input.Password)); err != nil{
        return c.Status(fiber.StatusUnauthorized).SendString("Invalid username or password\n")
    }


    // create JWT token
    claims := jwt.MapClaims{
        "id": user.ID,
        "username": user.Username,
        "email": user.Email,
        "exp": time.Now().Add(time.Hour * 24).Unix(), // this token expired in 24 hours
    }


    token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
    tokenString, err := token.SignedString(jwtSecret)
    if err != nil{
        return c.Status(500).SendString("Failed to generate token\n")
    }

    return c.JSON(fiber.Map{
        "message": "Login successful",
        "token": tokenString,
    })
}


func Register(c *fiber.Ctx) error{
    var user User
    
    if err := c.BodyParser(&user); err != nil{
        return err
    }

    // hash password

    hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
    if err != nil{
        return c.Status(400).SendString("Failed to hash password\n")
    }

    user.Password = string(hashedPassword)

    // check if username already exists
    var existing User
    if err := DB.Where("username = ?", user.Username).First(&existing).Error; err == nil{
        return c.Status(400).SendString("Username already exists\n")
    }

    if err := DB.Create(&user).Error; err != nil{
        return c.Status(400).SendString("Failed to create user\n")
    }

    // better success response
    return c.Status(fiber.StatusCreated).JSON(fiber.Map{
        "message": "User registered successfully",
        "user": fiber.Map{
            "id":       user.ID,
            "username": user.Username,
            "email":    user.Email,
        },
    })
}



func main(){
    app := fiber.New()

    // connect to Database
    var err error
    DB, err = gorm.Open(sqlite.Open("users.db"), &gorm.Config{})
    if err != nil{
        log.Fatal("Failed to connect to database")
    }

    // Migrate User struct to database
    // create db file if it doesn't exist
    err2 := DB.AutoMigrate(&User{})
    if err2 != nil{
        log.Fatal("Failed to migrate database")
    }

    // Routes
    app.Get("/api/test", func (c *fiber.Ctx) error{
        return c.SendString("welcome to goauth\n")
    }) 
    app.Get("/api/users", GetUsers)
    app.Post("/api/register", Register)
    app.Post("/api/login", Login)

    log.Fatal(app.Listen(":3000"))
}


