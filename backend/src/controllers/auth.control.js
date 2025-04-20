import bcrypt from "bcryptjs"
import User from "../models/user.model.js"
import { genToken } from "../lib/utils.js"
import cloudinary from "../lib/cloudinary.js"
import {protectRoute} from "../middleware/auth.middleware.js"


export const signup = async (req,res)=>{
    const {fullName, email, password} = req.body
    try{
        if(!fullName || !email || !password){
            return res.status(400).json({message:"All fields is mandatory"})
        }
        if(password.length < 6){
            return res.status(400).json({message:"Password must be ta least 6 characters"})
        }

        const user = await User.findOne({email})
        if(user){
            return res.status(400).json({message:"user already exist"})
        }

        const salt = await bcrypt.genSalt(10)
        const hashedPass = await bcrypt.hash(password, salt)

        const newUser = new User({
            fullName,
            email,
            password:hashedPass
        })
        if(newUser){
            // generate token
            genToken(newUser._id, res)
            await newUser.save()

            res.status(201).json({
                _id:newUser._id,
                fullName:newUser.fullName,
                email:newUser.email,
                profilePic:newUser.profilePic,
            })
        }   
        else{
            res.status(400).json({message:"Invalid information!"})
        }     
    }
    catch(error){
        res.status(500).json({message:"internal server error"})
        console.log("error in auth control in signup: ",error)
    }
}


export const login = async (req,res)=>{
    const {email, password} = req.body
    try{
        const user = await User.findOne({email})

        if(!user) return res.status(400).json({message: "Something wen wrong"})
        
       const isPasswordCorrect = await bcrypt.compare(password, user.password)

       if(! isPasswordCorrect) return res.status(400).json({message: "Something wen wrong"})
        
       genToken(user._id, res)

       res.status(200).json({
        _id:user._id,
        fullName:user.fullName,
        email:user.email,
        profilePic:user.profilePic,
       })
    }catch(error){
        console.log("error in login in auth contro :",error)
        res.status(500).json({message:"internal server error"})
    }
}


export const logout =  (req,res)=>{
    try{
        res.cookie("jwt", "",{maxAge:0})
        res.status(200).json({message:"Logout successfully"})
    }catch(error){
        console.log("error in login in auth contro :",error)
        res.status(500).json({message:"internal server error"})
    }
}




export const updateProfile = async (req, res) => {
  try {
    const { profilePic } = req.body;
    const userId = req.user._id;

    if (!profilePic) {
      return res.status(400).json({ message: "Profile Pic is required" });
    }

    // Upload to Cloudinary
    const uploadRes = await cloudinary.uploader.upload(profilePic, {
      resource_type: "auto", // Auto-detect the file type (image, video, etc.)
    });

    // Update the user's profile picture URL
    const updatedUser = await User.findByIdAndUpdate(
      userId,
      { profilePic: uploadRes.secure_url },
      { new: true }
    );

    res.status(200).json({ updatedUser });
  } catch (error) {
    console.log("Error in updating profile pic:", error);
    res.status(500).json({ message: "Internal server error", error });
  }
};

export const checkAuth = (req,res)=>{
    try{
        res.status(200).json(req.user);
    }
    catch(error){
        console.log("error in checking user :",error)
        res.status(500).json({message:"internal server error",error})
    }
}