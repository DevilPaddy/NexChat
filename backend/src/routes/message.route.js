import express from "express"
import { protectRoute } from "../middleware/auth.middleware.js"
import {getUsersForSidebar, getMessages, sentMessages} from "../controllers/message.control.js"

const router = express.Router()

router.get("/users", protectRoute, getUsersForSidebar)

router.get("/:id", protectRoute, getMessages)

router.post("/send/:id", protectRoute, sentMessages)
export default router