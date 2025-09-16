# CRUD Application - Flask

This is a Flask-based RESTful CRUD application that demonstrates how to manage records with advanced features.

## What the Code Does

- Implements **user registration and login** with password hashing and JWT authentication.
- Supports **role-based access control**: Admin users can create, update, and delete records; regular users can only read records.
- Provides endpoints to **create, read, update, and delete records** with input validation.
- Logs all changes with an **audit trail** capturing who did what and when.
- Supports **pagination and search** when listing records.
- Includes a **bulk delete** operation for efficiency.
- Returns meaningful HTTP status codes and error messages.
- Uses SQLite as the database (can be changed easily).
- Designed for secure and maintainable API development with Flask extensions like SQLAlchemy, Bcrypt, and JWT.

This app can be extended or integrated with a frontend or further enhanced with more features for production use.

---

To run, install the required Python packages (`flask`, `flask_sqlalchemy`, `flask_bcrypt`, `flask_jwt_extended`) and run the app with Python.
