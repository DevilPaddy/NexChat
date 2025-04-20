import express from "express"
import { login, logout, signup, checkAuth, updateProfile } from "../controllers/auth.control.js"
import {protectRoute} from "../middleware/auth.middleware.js"


const router = express.Router()

// signup route
router.post("/signup", signup)

// login route
router.post("/login", login)

// logout route
router.post("/logout", logout)

// change or update profile pic...
router.put("/update-profile", protectRoute, updateProfile)


router.get("/check", protectRoute, checkAuth)
export default router;
