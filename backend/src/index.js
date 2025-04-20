import express from "express";
import dotenv from "dotenv";
import cookieParser from "cookie-parser";
import cors from "cors";
import {app, server} from "./lib/socket.js"

import { connectDB } from "./lib/db.js";
import authRoutes from "./routes/auth.route.js";
import messageRoutes from "./routes/message.route.js";

dotenv.config();


const PORT = process.env.PORT;

app.use(cors({
  origin: "http://localhost:5173",
  credentials: true,
}));

// Middleware
app.use(express.json({ limit: '50mb' }));  
app.use(cookieParser());

// Routes
app.use("/api/auth", authRoutes);
app.use("/api/messages", messageRoutes);

server.listen(PORT, () => {
  console.log("Server is running on port:", PORT);
  connectDB();
});
