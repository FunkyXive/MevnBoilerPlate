<template>
    <div>
        <h1>Add an E-juice</h1>
        <form @submit.prevent="addE_juice">
            <div class="row">
                <div class="col-md-6">
                    <div class="form-group">
                        <label>Street Name And Number:</label>
                        <input
                            type="text"
                            class="form-control"
                            v-model="address.address"
                        />
                    </div>
                </div>
            </div>
            <div class="row">
                <div class="col-md-6">
                    <div class="form-group">
                        <label>City:</label>
                        <input
                            type="text"
                            class="form-control"
                            v-model="address.city"
                        />
                    </div>
                </div>
            </div>
            <div class="row">
                <div class="col-md-6">
                    <div class="form-group">
                        <label>Postal Code:</label>
                        <input
                            type="number"
                            class="form-control"
                            v-model="address.postalCode"
                        />
                    </div>
                </div>
            </div>
            <br />
            <div class="form-group">
                <button class="btn btn-primary">Create</button>
            </div>
        </form>
    </div>
</template>

<script>
export default {
    data() {
        return {
            address: {},
        };
    },
    methods: {
        addE_juice() {
            let uri = "http://localhost:4000/addresses/add";
            this.axios.post(uri, this.address).then(() => {
                this.$router.push({ name: "addresses" });
            });
        },
    },
};
</script>