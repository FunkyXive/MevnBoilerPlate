<template>
  <div>
    <nav class="purple accent-3">
      <div class="nav-wrapper">
        <ul class="nav-mobile">
          <li>
            <router-link to="/">some nav YYYYYYYYYYYYYYYYYYYEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEETttt</router-link>
          </li>
        </ul>
      </div>
    </nav><br />
    <div class="center-align">
      <img src="./assets/test.png"/>
    </div>
    <div class="container">
      <div class="row">
        <div class="col s4">
          <img src="./assets/logo.png"/>
        </div>
        <div class="col s4">
          <form>
            <div class="input-field">
              <input id="search" type="search" required>
              <label class="label-icon" for="search"><i class="material-icons">search</i></label>
              <i class="material-icons">close</i>
            </div>
          </form>
        </div>
        <div class="col s2 offset-s2">
          <ul class="collapsible">
            <li>
              <div class="collapsible-header"><i class="material-icons">shopping_cart</i>Shopping Cart</div>
              <div class="collapsible-body"><span>Lorem ipsum dolor sit amet.</span></div>
            </li>
          </ul>
        </div>
      </div>
      
      <nav class="purple accent-3">
      <ul class="nav-mobile">
        <li>
          <router-link to="/">Home</router-link>
        </li>
        <li>
          <router-link to="/e_juices">E-juice</router-link>
        </li>
        <li>
          <router-link to="/tanks_and_coils">Tanks and Coils</router-link>
        </li>
        <li>
          <router-link to="/batteries_and_mods">Batteries and Mods</router-link>
        </li>
        <li>
          <router-link to="/accessories">Accessories</router-link>
        </li>
        <li>
          <router-link to="/add_ejuice">Add E-juice</router-link>
        </li>
        <li>
          <router-link to="/add_address">Add Address</router-link>
        </li>
        <li>
          <router-link to="/add_order">Add Order</router-link>
        </li>
      </ul>
    </nav>
      <transition name="fade">
        <router-view></router-view>
      </transition>
    </div>
    <footer class="page-footer purple accent-3">
      <div class="container">
        <div class="row">
          <div class="col l6 s12">
            <h5 class="white-text">A/M Leasing</h5>
            <p class="grey-text text-lighten-4">Dronningensgade 107b st.t.v</p>
            <p class="grey-text text-lighten-4">5000 Odense C, Denmark</p>
            <p class="grey-text text-lighten-4">+45 67 68 91 02</p>
          </div>
        </div>
      </div>
      <div class="footer-copyright">
        <div class="container">© 2021 Steam n Smoke</div>
      </div>
    </footer>
  </div>
</template>

<style>
    .fade-enter-active, .fade-leave-active {
      transition: opacity .5s
    }
    .fade-enter, .fade-leave-active {
      opacity: 0
    }
</style>

<script>
    export default{
    }
</script>
