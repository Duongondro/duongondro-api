// Removes the sign-in token from the address bar and history. The token is in
// the fragment, so it never reached the server; this page makes no requests.
(function () {
  if (location.hash && history.replaceState) {
    history.replaceState(null, "", location.pathname);
  }
})();
