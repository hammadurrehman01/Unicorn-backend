import { model, Schema } from "mongoose";

const subscriptionSchema = new Schema({
    subscriber: {
        type: Schema.Types.ObjectId, // wo user jo subscribe krega
        ref: "User"
    },
    channel: {
        type: Schema.Types.ObjectId, // wo user jiska channel hoga
        ref: "User"
    },
}, { timestamps: true })

export const Subscription = model("Subscription", subscriptionSchema)