import re

from fastapi import HTTPException


class ValidationError(HTTPException):
    """Custom exception for validation errors."""

    def __init__(self, detail: str):
        super().__init__(status_code=400, detail=detail)


class InputValidator:
    """Comprehensive input validation utilities."""

    # Email validation regex (RFC 5322 compliant but simplified)
    EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")

    # Safe string regex (prevents XSS and injection)
    SAFE_STRING_REGEX = re.compile(r"^[a-zA-Z0-9\s\-_.,!?@#$%&*()+=\[\]{}|;:<>\/]+$")

    @staticmethod
    def validate_email(email: str) -> str:
        """Validate email format and length."""
        if not email:
            raise ValidationError("Email is required")

        email = email.strip().lower()

        if len(email) > 150:
            raise ValidationError("Email is too long (max 150 characters)")

        if not InputValidator.EMAIL_REGEX.match(email):
            raise ValidationError("Invalid email format")

        return email

    @staticmethod
    def validate_password(password: str) -> str:
        """Validate password strength requirements."""
        if not password:
            raise ValidationError("Password is required")

        if len(password) < 12:
            raise ValidationError("Password must be at least 12 characters long")

        if len(password) > 128:
            raise ValidationError("Password is too long (max 128 characters)")

        # Check for at least one uppercase letter
        if not re.search(r"[A-Z]", password):
            raise ValidationError("Password must contain at least one uppercase letter")

        # Check for at least one lowercase letter
        if not re.search(r"[a-z]", password):
            raise ValidationError("Password must contain at least one lowercase letter")

        # Check for at least one digit
        if not re.search(r"\d", password):
            raise ValidationError("Password must contain at least one digit")

        # Check for at least one special character
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            raise ValidationError(
                "Password must contain at least one special character"
            )

        # Check for common weak passwords
        weak_patterns = [
            "password",
            "123456",
            "qwerty",
            "admin",
            "letmein",
            "welcome",
            "monkey",
            "dragon",
            "master",
            "sunshine",
        ]
        password_lower = password.lower()
        for pattern in weak_patterns:
            if pattern in password_lower:
                raise ValidationError("Password contains common weak patterns")

        return password

    @staticmethod
    def validate_full_name(name: str | None) -> str | None:
        """Validate full name format."""
        if not name:
            return None

        name = name.strip()

        if len(name) > 100:
            raise ValidationError("Name is too long (max 100 characters)")

        if len(name) < 2:
            raise ValidationError("Name is too short (min 2 characters)")

        # Allow letters, spaces, hyphens, and apostrophes
        if not re.match(r"^[a-zA-Z\s\-\'\.]+$", name):
            raise ValidationError("Name contains invalid characters")

        return name

    @staticmethod
    def validate_department(department: str | None) -> str | None:
        """Validate department name."""
        if not department:
            return None

        department = department.strip()

        if len(department) > 100:
            raise ValidationError("Department name is too long (max 100 characters)")

        if not InputValidator.SAFE_STRING_REGEX.match(department):
            raise ValidationError("Department name contains invalid characters")

        return department

    @staticmethod
    def validate_otp_code(code: str) -> str:
        """Validate OTP code format."""
        if not code:
            raise ValidationError("OTP code is required")

        code = code.strip()

        if len(code) != 6:
            raise ValidationError("OTP code must be exactly 6 digits")

        if not code.isdigit():
            raise ValidationError("OTP code must contain only digits")

        return code

    @staticmethod
    def validate_request_type(request_type: str) -> str:
        """Validate request type."""
        valid_types = {"ANNUAL_LEAVE", "SICK_LEAVE", "EXPENSE", "IT_ACCESS", "ANON_HR"}

        request_type = request_type.upper().strip()

        if request_type not in valid_types:
            raise ValidationError(
                f"Invalid request type. Must be one of: {', '.join(sorted(valid_types))}"
            )

        return request_type

    @staticmethod
    def validate_request_payload(request_type: str, payload: dict) -> dict:
        """Validate request payload based on type."""
        required_fields = {
            "ANNUAL_LEAVE": ["start_date", "end_date", "reason"],
            "SICK_LEAVE": ["start_date", "days", "fit_note"],
            "EXPENSE": ["amount", "currency", "category", "description"],
            "IT_ACCESS": ["system", "access_level", "justification"],
            "ANON_HR": ["category", "description"],
        }

        if request_type not in required_fields:
            raise ValidationError(f"Unknown request type: {request_type}")

        fields = required_fields[request_type]

        # Check required fields
        for field in fields:
            if field not in payload:
                raise ValidationError(f"Missing required field: {field}")

        # Validate specific field types
        if request_type == "EXPENSE":
            try:
                amount = float(payload["amount"])
                if amount <= 0:
                    raise ValidationError("Amount must be positive")
                if amount > 1000000:
                    raise ValidationError("Amount is too large")
            except (ValueError, TypeError):
                raise ValidationError("Invalid amount format")

        if request_type == "SICK_LEAVE":
            try:
                days = int(payload["days"])
                if days <= 0:
                    raise ValidationError("Days must be positive")
                if days > 365:
                    raise ValidationError("Days value is too large")
            except (ValueError, TypeError):
                raise ValidationError("Invalid days format")

        # Validate text fields length
        text_fields = ["reason", "description", "justification", "fit_note", "category"]
        for field in text_fields:
            if payload.get(field) and len(str(payload[field])) > 1000:
                raise ValidationError(f"{field} is too long (max 1000 characters)")

        return payload

    @staticmethod
    def validate_notes(notes: str | None) -> str | None:
        """Validate approval notes."""
        if not notes:
            return None

        notes = notes.strip()

        if len(notes) > 1000:
            raise ValidationError("Notes are too long (max 1000 characters)")

        if not InputValidator.SAFE_STRING_REGEX.match(notes):
            raise ValidationError("Notes contain invalid characters")

        return notes

    @staticmethod
    def validate_uuid(uuid_str: str) -> str:
        """Validate UUID format."""
        import uuid as uuid_lib

        try:
            uuid_obj = uuid_lib.UUID(str(uuid_str))
            return str(uuid_obj)
        except ValueError:
            raise ValidationError("Invalid UUID format")

    @staticmethod
    def sanitize_string(input_string: str, max_length: int = 1000) -> str:
        """Sanitize string input to prevent injection attacks."""
        if not input_string:
            return ""

        input_string = str(input_string).strip()

        if len(input_string) > max_length:
            raise ValidationError(f"Input is too long (max {max_length} characters)")

        # Remove potentially dangerous characters
        dangerous_chars = ["<", ">", '"', "'", "&", "\x00", "\n", "\r"]
        for char in dangerous_chars:
            input_string = input_string.replace(char, "")

        return input_string
