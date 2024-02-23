fetch("/config")
.then((result) => { return result.json(); })
.then((data) => {
  //initialize Stripe.js
  const stripe = Stripe(data.publicKey);

  document.querySelector("#submitBtn").addEventListener("click", () => {
    fetch("/create-checkout-session")
    .then((result) => { return result.json(); })
    .then((data) => {
      console.log(data);
      //redirect to stripe checkout
      return stripe.redirectToCheckout({sessionId: data.sessionId})
    })
    .then((res) => {
      console.log(res);
    });
  });
});