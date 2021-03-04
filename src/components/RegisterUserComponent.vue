<template>
  <div>
    <h4>Register</h4>
    <form @submit.prevent="handleSubmit">
      <label for="email">Email</label>
      <div>
        <input id="email" type="text" v-model="email" required autofocus />
      </div>

      <label for="password">Password</label>
      <div>
        <input id="password" type="password" v-model="password" required />
      </div>

      <label for="password-confirm">Confirm Password</label>
      <div>
        <input
          id="password-confirm"
          type="password"
          v-model="password_confirmation"
          required
        />
      </div>

      <label for="address">Address</label>
      <div>
        <input id="address" type="text" v-model="address" required />
      </div>

      <label for="zipCode">Zip Code</label>
      <div>
        <input id="zipCode" type="number" v-model="zipCode" required />
      </div>

      <label for="city">City</label>
      <div>
        <input id="city" type="text" v-model="city" required />
      </div>

      <div class="form-group">
        <button class="btn btn-primary">Create</button>
      </div>
    </form>
  </div>
</template>
<script>
export default {
  props: ["nextUrl"],
  data() {
    return {
      email: "",
      password: "",
      password_confirmation: "",
      address: "",
      zipCode: "",
      city: "",
    };
  },
  methods: {
    handleSubmit(e) {
      e.preventDefault();

      if (
        this.password === this.password_confirmation &&
        this.password.length > 0
      ) {
        let url = "http://localhost:4000/user/add";
        this.axios
          .post(url, {
            email: this.email,
            password: this.password,
            address: this.address,
            zipCode: this.zipCode,
            city: this.city,
          })
          .then((response) => {
            localStorage.setItem("user", JSON.stringify(response.data.user));
            localStorage.setItem("jwt", response.data.token);

            if (localStorage.getItem("jwt") != null) {
              this.$emit("loggedIn");
              if (this.$route.params.nextUrl != null) {
                this.$router.push(this.$route.params.nextUrl);
              } else {
                this.$router.push("/");
              }
            }
          })
          .catch((error) => {
            console.error(error);
          });
      } else {
        this.password = "";
        this.password_confirmation = "";

        return alert("Passwords do not match");
      }
    },
  },
};
</script>