import { asyncHandler } from "../utils/asyncHandler.js";
import { ApiError } from "../utils/ApiError.js";
import { User } from "../models/user.model.js";
import { uploadOnCloudinary } from "../utils/cloudinary.js";
import { ApiResponse } from "../utils/ApiReponse.js";
import jwt from "jsonwebtoken";
import mongoose from "mongoose";

// get user details from frontnend ==>
// validation - not empty ====>
// check if user already exists ? via email or username ====>
// check for images, avatar ===>
// upload images, avatar on cloudinary ===>
// create user object or details and store in db ===>
// remove password and refresh token field from res ===>
// check for user creation ===>
// return res ===>

const options = {
    httpOnly: true,
    secure: true,
}

const registerUser = asyncHandler(async (req, res) => {
    const { fullName, email, password, username } = req.body;

    // checking if input field is not empty
    if ([fullName, email, password, username].some((field) => field?.trim() === "")) {
        throw new ApiError(400, "All fields are required")
    }

    // checking if given email or username already exists or not
    const existedUser = await User.findOne({
        $or: [{ username }, { email }]
    })
    if (existedUser) {
        throw new ApiError(409, "User with email or username already exists")
    }
    
    let avatarLocalPath;
    let coverImageLocalPath;

    // Check for avatar
    if (req.files?.avatar) {
        avatarLocalPath = req.files?.avatar[0]?.path;
    }

    // Check for cover image
    if (req.files && Array.isArray(req.files.coverImage) && req.files.coverImage.length > 0) {
        coverImageLocalPath = req.files.coverImage[0].path;
    }

    // Upload avatar and cover image to Cloudinary
    let avatarUploaded, coverImageUploaded;

    if (avatarLocalPath) {
        avatarUploaded = await uploadOnCloudinary(avatarLocalPath);
    }

    if (coverImageLocalPath) {
        coverImageUploaded = await uploadOnCloudinary(coverImageLocalPath);
    }
    // create user object to store in db
    const userDetails = await User.create({
        fullName,
        email,
        password,
        username: username?.toLowerCase(),
        avatar: avatarUploaded?.url || "",
        coverImage: coverImageUploaded?.url || "",
    })

    // removing password and refresh token field from res
    const createdUser = await User.findById(userDetails._id).select("-password -refreshToken");
    if (!createdUser) {
        throw new ApiError(500, "Something went wrong while registering a user");
    }

    return res.status(201).send(
        new ApiResponse(200, "User registered successfully", createdUser)
    )
});

const generateAccessAndRefreshTokens = async (userId) => {
    try {
        const user = await User.findById(userId);
        const accessToken = user.generateAccessToken();
        const refreshToken = user.generateRefreshToken();

        user.refreshToken = refreshToken;
        user.save({ validateBeforeSave: false });

        return { accessToken, refreshToken }

    } catch (error) {
        throw new ApiError(500, "Something went wrong while generating refresh and access token")
    }

}

const loginUser = asyncHandler(async (req, res) => {
    const { email, password } = req.body;

    if (!(email && password)) {
        throw new ApiError(400, "username or password must required")
    }

    const user = await User.findOne({
        $or: [{ email }, { password }]
    })
    if (!user) {
        throw new ApiError(404, "user with this email is not exist!")
    }

    const isPasswordValid = await user?.isPasswordCorrect(password);

    if (!isPasswordValid) {
        throw new ApiError(401, "Password is not correct")
    }

    const { accessToken, refreshToken } = await generateAccessAndRefreshTokens(user._id)

    const loggedInUser = await User.findById(user._id).select("-password -refreshToken");

    return res
        .status(200)
        .cookie("accessToken", accessToken, options)
        .cookie("refreshToken", refreshToken, options)
        .json(
            new ApiResponse(200,
                {
                    user: loggedInUser,
                    accessToken,
                    refreshToken
                },
                "User logged in successfully"
            )
        )
})

const logoutUser = asyncHandler(async (req, res) => {
    await User.findByIdAndUpdate(req.user._id, {
        $set: { refreshToken: undefined }
    },
        {
            new: true
        }
    )

    return res
        .status(200)
        .clearCookie("accessToken", options)
        .clearCookie("refreshToken", options)
        .json(new ApiResponse(200, {}, "User logged out successfully"))
})

const handleRefreshAccessToken = asyncHandler(async (req, res) => {
    try {
        const incomingRefreshToken = req.cookies.refreshToken || req.body.refreshToken;

        if (!incomingRefreshToken) {
            throw new ApiError(401, "unauthorized request")
        }

        const decodedToken = jwt.verify(incomingRefreshToken, process.env.REFRESH_TOKEN_SECRET);
       
        const user = await User.findById(decodedToken?._id);

        if (!user) {
            throw new ApiError(401, "unauthorized request")
        }

        if (incomingRefreshToken !== user?.refreshToken) {
            throw new ApiError(401, "Refresh token is expired or used")
        }

        const { accessToken, refreshToken } = await generateAccessAndRefreshTokens(user._id);

        return res
            .status(200)
            .cookie("accessToken", accessToken, options)
            .cookie("refreshToken", refreshToken, options)
            .json(
                new ApiResponse(
                    200,
                    { accessToken, refreshToken },
                    "Access token refreshed"
                )
            )
    } catch (error) {
        throw new ApiError(500, "Something went wrong while refreshing refresh token")
    }

})

const changeCurrentPassword = asyncHandler(async (req, res) => {
    const { oldPassword, newPassword, confirmPassword } = req.body;

    if (!(oldPassword || confirmPassword)) {
        throw new ApiError(404, "All fields are required")
    }

    const user = await User.findById(req.user._id);

    const isPasswordCorrect = await user.isPasswordCorrect(oldPassword);

    if (!isPasswordCorrect) {
        throw new ApiError(400, "Passwords are not matched")
    }

    user.password = newPassword

    await user.save({ validateBeforeSave: false });

    return res
        .status(200)
        .json(
            new ApiResponse(200, {}, "Password has been changed")
        )


})

const getCurrentUser = asyncHandler(async (req, res) => {
    return res.status(200)
        .json(new ApiResponse(
            200,
            req.user,
            "Current User is fetched successfully"
        ))
})

const updateAccountDetails = asyncHandler(async (req, res) => {
    const { fullName, email } = req.body;

    if (!(fullName || email)) {
        throw new ApiError(400, "All fiels are required")
    }

    const user = await User.findByIdAndUpdate(
        req.user._id,
        {
            $set: {
                fullName,
                email
            }
        },
        { new: true }
    ).select("-password")

    return res.status(200)
        .json(new ApiResponse(200, user, "Account details updated successfully"))


})

const updateUserAvatar = asyncHandler(async (req, res) => {
    const avatarLocalPath = req.file?.path;
    if (!avatarLocalPath) {
        throw new ApiError(400, "Avatar file is missing")
    }

    const uploadedAvatar = uploadOnCloudinary(avatarLocalPath);
    if (!uploadedAvatar.url) {
        throw new ApiError(400, "Error while uploading on avatar");
    }

    const user = await User.findByIdAndUpdate(
        req.user?._id,
        {
            $set: {
                avatar: uploadedAvatar.url
            }
        },
        { new: true }
    ).select("-password");

    return res.status(200)
        .json(new ApiResponse(200, user, "avatar updated successfully"))
})

const updateUserCoverImage = asyncHandler(async (req, res) => {
    const coverImageLocalPath = req.file?.path;
    if (!coverImageLocalPath) {
        throw new ApiError(400, "cover image file is missing")
    }

    const uploadedCoverImage = uploadOnCloudinary(coverImageLocalPath);
    if (!uploadedCoverImage.url) {
        throw new ApiError(400, "Error while uploading on cover image");
    }

    const user = await User.findByIdAndUpdate(
        req.user?._id,
        {
            $set: {
                coverImage: uploadedCoverImage.url
            }
        },
        { new: true }
    ).select("-password");

    return res.status(200)
        .json(new ApiResponse(200, user, "cover image updated successfully"))
})

const getUserChannelProfile = asyncHandler(async (req, res) => {
    const { username } = req.params;

    if (!username?.trim()) {
        throw new ApiError(400, "username is missing")
    }

    const channel = await User.aggregate([
        {
            $match: {
                username: username?.toLowerCase()
            },
            $lookup: {
                from: "subscriptions",
                localField: "_id",
                foreignField: "channel",
                as: "subscribers"
            },
            $lookup: {
                from: "subscriptions",
                localField: "_id",
                foreignField: "subscriber",
                as: "subscribedTo"
            },
            $addFields: {
                subscribersCount: {
                    $size: "subscribers"
                },
                channelSubscribedToCount: {
                    $size: "subscribedTo"
                },
                isSubscribed: {
                    $cond: {
                        if: {
                            $in: [req.user?._id, "$subscribers.subscriber"]
                        },
                        then: true,
                        else: false
                    }
                }
            },
            $project: {
                fullname: 1,
                username: 1,
                subscribersCount: 1,
                channelSubscribedToCount: 1,
                isSubscribed: 1,
                coverImage: 1,
                avatar: 1,
                email: 1,
            }
        }
    ])

    if (!channel?.length) {
        throw new ApiError(404, "channel not found or not exist")
    }

    return res.status(200)
        .json(new ApiResponse(200, channel[0], "user channel fetched successfully"))
})

const getWatchHistory = asyncHandler(async (req, res) => {
    const user = await User.aggregate([
        {
            $match: {
                _id: new mongoose.Types.ObjectId(req.user._id)
            }
        },
        {
            $lookup: {
                from: "videos",
                localFiels: "watchHistory",
                foreignField: "_id",
                as: "watchHistory",
                pipeline: [
                    {
                        $lookup: {
                            from: "users",
                            localField: "owner",
                            foreignField: "_id",
                            as: "owner",
                            pipeline: [
                                {
                                    $project: {
                                        fullName: 1,
                                        username: 1,
                                        avatar: 1,
                                    }
                                }
                            ]
                        }
                    },
                    {
                        $addFields: {
                            owner: {
                                $first: "$owner"
                            }
                        }
                    }
                ]
            }
        }
    ])

    return res.status(200)
        .json(
            new ApiResponse(200,
                user[0].watchHistory,
                "Watch history fetched successfully"
            ))
})
// TODO: delete previous avatar after updating
export {
    registerUser,
    loginUser,
    logoutUser,
    handleRefreshAccessToken,
    changeCurrentPassword,
    getCurrentUser,
    updateAccountDetails,
    updateUserAvatar,
    updateUserCoverImage,
    getUserChannelProfile,
    getWatchHistory,
}