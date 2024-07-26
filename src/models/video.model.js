import mongoose, { Schema } from "mongoose";
import mongooseAggregatePaginate from "mongoose-aggregate-paginate-v2";

const videoSchema = new Schema({
    videoFile: {
        type: String, // url
        required: true
    },
    thumbnail: {
        type: String, // url
        required: true
    },
    title: {
        type: String, // url
        required: true
    },
    description: {
        type: String, // url
        required: true
    },
    duration: {
        type: Number, // url
        required: true
    },
    views: {
        type: Number, // url
        default: 0
    },
    isPublished: {
        type: Boolean, // url
        default: true
    },
    owner: {
        type: Schema.Types.ObjectId, // url
        ref: "User"
    },
},
    { timeStamps: true });



videoSchema.plugin(mongooseAggregatePaginate)
export const Video = mongoose.model('Video', videoSchema);