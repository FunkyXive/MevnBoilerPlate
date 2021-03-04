const mongoose = require('mongoose');
const Schema = mongoose.Schema;


let Address = new Schema(
    {
        address: {
            type: String,
        },
        city: {
            type: String,
        },
        postalCode: {
            type: Number,
        },

    },
    {
        collection: "addresses",
    }
);

module.exports = mongoose.model("Address", Address);
