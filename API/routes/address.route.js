// post.model.js

const express = require("express");
const addressRoutes = express.Router();

// Require Address model in our routes module
let Address = require("../models/address.model");

// Defined store route
addressRoutes.route("/add").post(function(req, res) {
    let address = new Address(req.body);
    address.save()
        .then(() => {
            res.status(200).json({
                business: "business in added successfully",
            });
        })
        .catch(() => {
            res.status(400).send("unable to save to database");
        });
});

// Defined get data(index or listing) route
addressRoutes.route("/").get(function(req, res) {
    Address.find(function(err, posts) {
        if (err) {
            res.json(err);
        } else {
            res.json(posts);
        }
    });
});

// Defined edit route
addressRoutes.route("/edit/:id").get(function(req, res) {
    let id = req.params.id;
    Address.findById(id, function(err, post) {
        if (err) {
            res.json(err);
        }
        res.json(post);
    });
});

//  Defined update route
addressRoutes.route("/update/:id").post(function(req, res) {
    Address.findById(req.params.id, function(err, post) {
        if (!post) res.status(404).send("data is not found");
        else {
            post.address = req.body.address;
            post.city = req.body.city;
            post.postalCode = req.body.postalCode;
            post.save()
                .then(() => {
                    res.json("Update complete");
                })
                .catch(() => {
                    res.status(400).send("unable to update the database");
                });
        }
    });
});

// Defined delete | remove | destroy route
addressRoutes.route("/delete/:id").delete(function(req, res) {
    Address.findByIdAndRemove({ _id: req.params.id }, function(err) {
        if (err) res.json(err);
        else res.json("Successfully removed");
    });
});

module.exports = addressRoutes;
