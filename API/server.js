// server.js

const express = require('express');
const app = express();
const bodyParser = require('body-parser');
const PORT = 4000;
const cors = require('cors');
const mongoose = require('mongoose');
const config = require('./DB.js');
const addressRoute = require('./routes/address.route')
const userRoute = require('./routes/user.route')
const AdminBro = require('admin-bro')
const AdminBroExpress = require('@admin-bro/express')
const AdminBroMongoose = require('@admin-bro/mongoose')
const bcrypt = require('bcrypt')

const Address = require('./models/address.model')
const User = require('./models/user.model')

AdminBro.registerAdapter(AdminBroMongoose)

mongoose.Promise = global.Promise;
const connection = mongoose.connect(config.DB, { useNewUrlParser: true }).then(
    () => { console.log('Database is connected') },
    err => { console.log('Can not connect to the database' + err) }
)

const canModifyUsers = ({ currentAdmin }) => currentAdmin && currentAdmin.role == 'admin'

const adminBro = new AdminBro({
    resources: [Address, {
        resource: User,
        options: {
            properties: {
                encryptedPassword: {
                    isVisible: false,
                },
                password: {
                    type: 'string',
                    isVisible: {
                        list: false,
                        edit: true,
                        filter: false,
                        show: false,
                    },
                },
            },
            actions: {
                new: {
                    before: async(request) => {
                        if (request.payload.password) {
                            request.payload = {
                                ...request.payload,
                                encryptedPassword: await bcrypt.hash(request.payload.password, 10),
                                password: undefined,
                            }
                        }
                        return request
                    },
                },
                edit: { isAccessible: canModifyUsers },
                delete: { isAccessible: canModifyUsers },
                new: { isAccessible: canModifyUsers },
            },
        }
    }],
    rootPath: '/admin',
})

const router = AdminBroExpress.buildAuthenticatedRouter(adminBro, {
    authenticate: async(email, password) => {
        const user = await User.findOne({ email })
        if (user) {
            const matched = await bcrypt.compare(password, user.encryptedPassword)
            if (matched && user.role != 'normal') {
                return user
            }
        }
        return false
    },
    cookiePassword: 'secret-password',
})

app.use(cors())
app.use(adminBro.options.rootPath, router)
app.use(bodyParser.urlencoded({ extended: true }))
app.use(bodyParser.json())

app.use('/addresses', addressRoute);
app.use('/user', userRoute)

app.listen(PORT, function() {
    console.log('Server is running on Port:', PORT)
})