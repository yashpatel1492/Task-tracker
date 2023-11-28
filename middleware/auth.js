import { User } from "../models/user.js";
import jwt from "jsonwebtoken";

export const isAuthenticated = async (req, res, next) => {
    try {
        const { token } = req.cookies;

        if (!token) {
            return res.status(401).json({
                success: false,
                message: "Please log in first",
            });
        }

        const jwtToken = process.env.JWTTOKEN || 'defaultSecret';
        const decoded = jwt.verify(token, jwtToken);

        req.user = await User.findById(decoded);

        next();
    } catch (error) {
        if (error instanceof jwt.TokenExpiredError) {
            return res.status(401).json({
                success: false,
                message: "Token has expired",
            });
        }

        if (error instanceof jwt.JsonWebTokenError) {
            return res.status(401).json({
                success: false,
                message: "Invalid token",
            });
        }

        // Log the error for further investigation
        console.error(`Authentication error: ${error.message}`);
        
        return res.status(500).json({
            success: false,
            message: "Internal server error",
        });
    }
};