import Vue from "vue";
import App from "./App.vue";
import '@fortawesome/fontawesome-free/css/all.css'
import '@fortawesome/fontawesome-free/js/all.js'
import 'materialize-css/dist/css/materialize.min.css'
import 'materialize-css/dist/js/materialize.min'
import 'material-design-icons/iconfont/material-icons.css'
import 'materialize-css'
import VueRouter from "vue-router";
Vue.use(VueRouter);

import VueAxios from "vue-axios";
import axios from "axios";

Vue.use(VueAxios, axios);

Vue.config.productionTip = false;

import HomeComponent from "./components/HomeComponent.vue";
import AddAddressComponent from "./components/AddAddressComponent.vue"
import RegisterUserComponent from "./components/RegisterUserComponent.vue"
import LoginUserComponent from "./components/LoginUserComponent.vue"



const routes = [{
        name: "home",
        path: "/",
        component: HomeComponent,
    },
    {
        name: "addAddress",
        path: "/add_address",
        component: AddAddressComponent
    },
    {
        name: "registerUser",
        path: "/register",
        component: RegisterUserComponent,
        meta: {
            guest: true
        }
    },
    {
        name: "loginUser",
        path: "/login",
        component: LoginUserComponent,
        meta: {
            guest: true
        }
    },
];

const router = new VueRouter({ mode: "history", routes: routes });

router.beforeEach((to, from, next) => {
    if (to.matched.some(record => record.meta.requiresAuth)) {
        if (localStorage.getItem("jwt") == null) {
            next({
                path: '/login',
                params: { nextUrl: to.fullPath }
            })
        } else {
            let user = JSON.parse(localStorage.getItem('user'))
            if (to.matched.some(record => record.meta.is_admin)) {
                if (user.is_admin == 1) {
                    next()
                } else {
                    next({ name: 'userboard' })
                }
            } else {
                next()
            }
        }
    } else if (to.matched.some(record => record.meta.guest)) {
        if (localStorage.getItem('jwt') == null) {
            next()
        } else {
            next({ name: 'userboard' })
        }
    } else {
        next()
    }
})

new Vue(Vue.util.extend({ router }, App)).$mount("#app");