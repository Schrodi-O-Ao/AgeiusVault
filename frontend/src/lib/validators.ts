import { z } from 'zod';

export const registerSchema = z.object({
  full_name: z.string().min(2, "At least 2 characters").max(100, "Max 100 characters"),
  email: z.string().email("Enter a valid email"),
  password: z.string().min(12, "Minimum 12 characters")
    .regex(/[A-Z]/, "Must contain uppercase")
    .regex(/[a-z]/, "Must contain lowercase")
    .regex(/[0-9]/, "Must contain a number")
    .regex(/[^A-Za-z0-9]/, "Must contain a symbol"),
  confirmPassword: z.string()
}).refine((data) => data.password === data.confirmPassword, {
  message: "Passwords do not match",
  path: ["confirmPassword"],
});

export const loginSchema = z.object({
  email: z.string().email("Enter a valid email"),
  password: z.string()
});

export const totpSchema = z.object({
  totp_code: z.string().length(6, "Code must be 6 digits")
});
