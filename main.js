var crypt, decryptor;
var servpubkey;
var token;
var pagenum = 0;
// Call this code when the page is done loading.
jQuery(document).ready(function($) {
  $('#username').keyup(function(event) {
    if(event.target.checkValidity()){
      event.target.classList.remove('is-invalid');
      event.target.classList.add('is-valid');
      if($('#password').hasClass('is-valid')){
          $('#loginFormSubmit').prop('disabled', false);
        }
    }
    else{
      event.target.classList.remove('is-valid');
      event.target.classList.add('is-invalid');
      $('#loginFormSubmit').prop('disabled', true);
    }
    
  });
  $('#password').keyup(function(event) {
    $('#username').keyup();
    if(event.target.checkValidity()){
      event.target.classList.remove('is-invalid');
      event.target.classList.add('is-valid');
      if($('#username').hasClass('is-valid')){
          $('#loginFormSubmit').prop('disabled', false);
        }
    }
    else{
      event.target.classList.remove('is-valid');
      event.target.classList.add('is-invalid');
      $('#loginFormSubmit').prop('disabled', true);
    }
  });
  $('#newusername').keyup(function(event) {
    if(event.target.checkValidity()){
      event.target.classList.remove('is-invalid');
      event.target.classList.add('is-valid');
      if($('#newpassword').hasClass('is-valid')){
        if($('#newpassconfirm').hasClass('is-valid')){
          $('#newUserFormSubmit').prop('disabled', false);
        }
      }
    }
    else{
      event.target.classList.remove('is-valid')
      event.target.classList.add('is-invalid');
      $('#newUserFormSubmit').prop('disabled', true);
    }
    
  });
  $('#newpassword').keyup(function(event) {
    if(event.target.checkValidity()){
      event.target.classList.remove('is-invalid');
      event.target.classList.add('is-valid');
      if($('#newusername').hasClass('is-valid')){
        if($('#newpassconfirm').hasClass('is-valid')){
          $('#newUserFormSubmit').prop('disabled', false);
        }
      }
    }
    else{
      var errmsg = "";
      var haslen = new RegExp(".{8,128}");
      var haslower = new RegExp("[a-z]");
      var hasupper = new RegExp("[A-Z]");
      var hasnum = new RegExp("[0-9]");
      var haschars = new RegExp("[^\\w!#$%&*<=>?@~]");
      if(!(haslen.test(event.target.value))){
        errmsg += "Must be 8-128 characters<br>";
      }
      if(!(haslower.test(event.target.value))){
        errmsg += "Must have at least one lowercase character<br>";
      }
      if(!(hasupper.test(event.target.value))){
        errmsg += "Must have at least one uppercase character<br>";
      }
      if(!(hasnum.test(event.target.value))){
        errmsg += "Must have at least one number<br>";
      }
      if(haschars.test(event.target.value)){
        errmsg += "Must not have characters that are not alphanumeric or !#$%&*<=>?@~]<br>";
      }
      $('#newpassword-feedback').html(errmsg);
      event.target.classList.remove('is-valid');
      event.target.classList.add('is-invalid');
      $('#newUserFormSubmit').prop('disabled', true);
    }
  });
  $('#newpassconfirm').keyup(function(event) {
    if(event.target.value == $('#newpassword').val()){
      event.target.classList.remove('is-invalid');
      event.target.classList.add('is-valid');
      if($('#newpassword').hasClass('is-valid')){
        if($('#newusername').hasClass('is-valid')){
          $('#newUserFormSubmit').prop('disabled', false);
        }
      }
    }
    else{
      event.target.classList.remove('is-valid');
      event.target.classList.add('is-invalid');
      $('#newUserFormSubmit').prop('disabled', true);
    }
    
  });
  $('#loginForm').submit(function(e) {
    e.preventDefault();
    if($('#loginFormSubmit').hasClass('disabled')) {
      e.stopPropagation();
      return;
    }
    crypt = new JSEncrypt(1024);
    $.get('https://eserver-tfleck.c9users.io/rsa-pub-xxx.txt', function(data) {
      servpubkey = data;
      var enc = new JSEncrypt();
      enc.setPublicKey(servpubkey);
      var encrypted = "";
      var username = $('#username').val();
      var pass = $('#password').val();
      var payload = username+","+pass+","+crypt.getPublicKey();
      var i;
      for(i=0;(i+85)<=payload.length;i+=85){
        var temp_payload = payload.substring(i,i+85);
        encrypted += enc.encrypt(temp_payload);
      }
      if(i < payload.length){
        var temp_payload = payload.substring(i,payload.length);
        encrypted += enc.encrypt(temp_payload);
      }
      getToken(encrypted);
    },"text");
  });
  $('#newUserForm').submit(function(e) {
    e.preventDefault();
    if($('#newUserFormSubmit').hasClass('disabled')) {
      e.stopPropagation();
      return;
    }
    crypt = new JSEncrypt(1024);
    $.get('https://eserver-tfleck.c9users.io/rsa-pub-xxx.txt', function(data) {
      servpubkey = data;
      var enc = new JSEncrypt();
      enc.setPublicKey(servpubkey);
      var encrypted = "";
      var username = $('#newusername').val();
      var pass = $('#newpassword').val();
      var payload = username+","+pass+","+crypt.getPublicKey();
      var i;
      for(i=0;(i+85)<=payload.length;i+=85){
        var temp_payload = payload.substring(i,i+85);
        encrypted += enc.encrypt(temp_payload);
      }
      if(i < payload.length){
        var temp_payload = payload.substring(i,payload.length);
        encrypted += enc.encrypt(temp_payload);
      }
      addUser(encrypted);
    },"text");
  });
  $('#sendMsgForm').submit(function(e) {
    e.preventDefault();
    $.get('https://eserver-tfleck.c9users.io/rsa-pub-xxx.txt', function(data) {
      servpubkey = data;
      var enc = new JSEncrypt();
      enc.setPublicKey(servpubkey);
      var encrypted = "";
      var touser = $('#toUser').val();
      var message = $('#msgToSend').val();
      var payload = token+","+touser;
       var i;
      for(i=0;(i+85)<=payload.length;i+=85){
        var temp_payload = payload.substring(i,i+85);
        var temp_enc = enc.encrypt(temp_payload);
        encrypted += temp_enc;
      }
      if(i < payload.length){
        var temp_payload = payload.substring(i,payload.length);
        var temp_enc = enc.encrypt(temp_payload);
        encrypted += temp_enc;
      }
       $.post('https://eserver-tfleck.c9users.io/cgi-bin/getUserPub.cgi',encrypted, function(result) {
        if(result == "0"){
         console.log("failed");
       }
       else if(result == "1"){
         console.log("invalid input");
       }
       else{
         var decrypted = "";
         for(i=0;(i+174)<=result.length;i+=174){
           var temp_payload = result.substring(i,i+174);
           var decr = crypt.decrypt(temp_payload);
           decrypted += decr;
         }
         if(i < result.length){
           var temp_payload = result.substring(i,result.length);
           var decr = crypt.decrypt(temp_payload);
           decrypted += decr;
         }
         var encryptor = new JSEncrypt();
         encryptor.setPublicKey(decrypted);
         var enc_message = "";
          payload = message;
          for(i=0;(i+85)<=payload.length;i+=85){
            var temp_payload = payload.substring(i,i+85);
            var temp_enc = encryptor.encrypt(temp_payload);
            enc_message += temp_enc;
          }
          if(i < payload.length){
            var temp_payload = payload.substring(i,payload.length);
            var temp_enc = encryptor.encrypt(temp_payload);
            enc_message += temp_enc;
          }
         encrypted = "";
         payload = token+","+touser+","+enc_message;
          for(i=0;(i+85)<=payload.length;i+=85){
            var temp_payload = payload.substring(i,i+85);
            var temp_enc = enc.encrypt(temp_payload);
            encrypted += temp_enc;
          }
          if(i < payload.length){
            var temp_payload = payload.substring(i,payload.length);
            var temp_enc = enc.encrypt(temp_payload);
            encrypted += temp_enc;
          }
          sendMessage(encrypted);
           }
      },"text");
      
    },"text");
  });
  $('#getPrivForm').submit(function(e) {
    e.preventDefault();
    console.log("priv form submitted");
    decryptor = new JSEncrypt();
    decryptor.setPrivateKey($('#privKeyIn').val());
    $('#getPrivModal').modal('toggle');
    loadInbox(1,20);
  });
  $(document).on("click", "#refreshBtn", function(){
    loadInbox(1,20);
  });
  $(document).on("click", "#logoutBtn", function(){
      $.get('https://eserver-tfleck.c9users.io/rsa-pub-xxx.txt', function(data) {
        servpubkey = data;
        var enc = new JSEncrypt();
        enc.setPublicKey(servpubkey);
        var encrypted = "";
        var payload = token;
        var i;
        for(i=0;(i+85)<=payload.length;i+=85){
          var temp_payload = payload.substring(i,i+85);
          encrypted += enc.encrypt(temp_payload);
        }
        if(i < payload.length){
          var temp_payload = payload.substring(i,payload.length);
          encrypted += enc.encrypt(temp_payload);
        }
        logoutUser(encrypted);
      },"text");
    });
    $(document).on("click", "#pageBackward", function(){
      if(pagenum > 0){
        pagenum -= 1;
        loadInbox(1+(20*pagenum),20+(20*pagenum));
      }
      
    });
    $(document).on("click", "#pageForward", function(){
      if(pagenum < 98){
        pagenum += 1;
        loadInbox(1+(20*pagenum),20+(20*pagenum));
      }
    });
    $(window).on("beforeunload", function() { 
      /*
      $.get('https://eserver-tfleck.c9users.io/rsa-pub-xxx.txt', function(data) {
        servpubkey = data;
        var enc = new JSEncrypt();
        enc.setPublicKey(servpubkey);
        var encrypted = "";
        var payload = token;
        var i;
        for(i=0;(i+85)<payload.length;i+=85){
          var temp_payload = payload.substring(i,i+85);
          encrypted += enc.encrypt(temp_payload);
        }
        if(i < payload.length){
          var temp_payload = payload.substring(i,payload.length);
          encrypted += enc.encrypt(temp_payload);
        }
        logoutUser(encrypted);
      },"text");
      */
    });
});
function getToken( myData ){
  $.post('https://eserver-tfleck.c9users.io/cgi-bin/getToken.cgi',myData, function(result) {
    if(result == "0"){
     console.log("failed");
     $('#username').removeClass('is-valid');
     $('#password').removeClass('is-valid');
     $('#username').addClass('is-invalid');
     $('#password').addClass('is-invalid');
     $('#loginFormSubmit').prop('disabled', false);
   }
   else if(result == "1"){
     console.log("invalid input");
     $('#username').removeClass('is-valid');
     $('#password').removeClass('is-valid');
     $('#username').addClass('is-invalid');
     $('#password').addClass('is-invalid');
     $('#loginFormSubmit').prop('disabled', false);
   }
   else{
     var decrypted = "";
     var i;
     for(i=0;(i+174)<=result.length;i+=174){
       var temp_payload = result.substring(i,i+174);
       var decr = crypt.decrypt(temp_payload);
       decrypted += decr;
     }
     if(i < result.length){
       var temp_payload = result.substring(i,result.length);
       var decr = crypt.decrypt(temp_payload);
       decrypted += decr;
     }
     token = decrypted;
    if(token == "0"){
      console.log("error");
    }
    else{
      $('#getPrivModal').modal('toggle');
    }
   }
  },"text");
}
function addUser( myData ){
  $.post('https://eserver-tfleck.c9users.io/cgi-bin/addUser.cgi',myData, function(result) {
    if(result == "0"){
     console.log("failed");
   }
   else if(result == "1"){
     $(`<div class="alert alert-danger alert-dismissible fade in show" id="newalert-error">Couldn\'t create user, maybe try 
     another username<button type="button" class="close" data-dismiss="alert" aria-label="Close">
     <span aria-hidden="true">&times;</span>
     </button></div>`).insertBefore('#newUserForm');
     console.log("invalid input");
   }
   else{
     document.getElementById("newUserForm").reset(); 
     $('#privKeyModalBody').html(crypt.getPrivateKey().replace(/\n/g, "<br />")+"<br>");
     $('#privKeyModal').modal('toggle');
   }
  },"text");
}
function sendMessage( myData ){
  $.post('https://eserver-tfleck.c9users.io/cgi-bin/sendMessage.cgi',myData, function(result) {
    if(result == "0"){
     console.log("failed");
   }
   else if(result == "1"){
     console.log("invalid input");
   }
   else{
     console.log("success");
     $('#sendMsgModal').modal('toggle');
   }
  },"text");
}
function loadInbox(msgnum, msgmax){
  $("#container").fadeOut(300, function(done){
      $("#container").html(`
      <div class="row justify-content-center">
      <div class="col-10">
      <br>
      <h3>Downloading and decrypting inbox...</h3>
      <br>
      <div class="progress">
        <div class="progress-bar progress-bar-striped progress-bar-animated" aria-valuenow="0" aria-valuemin="0" aria-valuemax="100" id="progressBar" role="progressbar" style="width: 0%"></div>
      </div>
      </div>
      </div>
      `);
      $("#container").fadeIn(300, function(done) {
        $.get('https://eserver-tfleck.c9users.io/inbox.html', function(data) {
          //console.log(data);
          $("#container").after(data);
          loadMessage( msgnum,msgmax);
        });
      });
    });
}
function loadMessage(msgnum, msgmax){
  $.get('https://eserver-tfleck.c9users.io/rsa-pub-xxx.txt', function(data) {
      servpubkey = data;
      var enc = new JSEncrypt();
      enc.setPublicKey(servpubkey);
      var encrypted = "";
      var payload = token+","+msgnum;
      var i;
      for(i=0;(i+85)<=payload.length;i+=85){
        var temp_payload = payload.substring(i,i+85);
        encrypted += enc.encrypt(temp_payload);
      }
      if(i < payload.length){
        var temp_payload = payload.substring(i,payload.length);
        encrypted += enc.encrypt(temp_payload);
      }
      getMessage(encrypted, msgnum, msgmax);
    },"text");
}
function getMessage(myData, msgnum, msgmax){
  $.post('https://eserver-tfleck.c9users.io/cgi-bin/getMessage.cgi',myData, function(result) {
    if(result == "0"){
     console.log("failed");
     inboxFinished();
   }
   else if(result == "1"){
     console.log("invalid input");
     inboxFinished();
   }
   else{
     var decrypted = "";
     var i;
     for(i=0;(i+174)<=result.length;i+=174){
       var temp_payload = result.substring(i,i+174);
       var decr = crypt.decrypt(temp_payload);
       decrypted += decr;
     }
     if(i < result.length){
       var temp_payload = result.substring(i,result.length);
       var decr = crypt.decrypt(temp_payload);
       decrypted += decr;
     }
     var split = decrypted.indexOf(',');
     var split2 = decrypted.indexOf(',',split+1);
     var timestamp = decrypted.substring(0,split);
     var userFrom = decrypted.substring(split+1,split2);
     var encMsg = decrypted.substring(split2+1);
     var plain = "";
     var j;
     for(j=0;(j+172)<=encMsg.length;j+=172){
       var temp_payload = encMsg.substring(j,j+172);
       var decr = decryptor.decrypt(temp_payload);
       plain += decr;
     }
     if(j < encMsg.length){
       var temp_payload = encMsg.substring(j);
       var decr = decryptor.decrypt(temp_payload);
       plain += decr;
     }
     var msgrow = '<tr><th scope="row">'+msgnum+'</th><td style="min-width: 300px;">'+timestamp+'</td><td>'+userFrom+'</td><td>'+plain+'</td></tr>';
     $('#msgTable tbody').append(msgrow);
     if(msgnum+1 <= msgmax){
        updateProgress(msgnum/msgmax*100);
        loadMessage( msgnum+1,msgmax);
     }
     else{
       inboxFinished();
     }
   }
  },"text");
}
function updateProgress(progress){
  if(progress <= 100){
    $('.progress-bar').css('width',progress+'%').attr('aria-valuenow', progress);
  }
}
function inboxFinished(){
  updateProgress(100);
  $("#container").fadeOut(500, function(done){
    var temp = $('#inbox').html();
    $('#inbox').remove();
    $("#container").html(temp);
    $('#inbox').css('display','block');
    document.getElementById("currentPage").text = pagenum+1;
    $("#container").fadeIn(300, function(done){
    });
  });
}
function logoutUser( myData ){
  $.post('https://eserver-tfleck.c9users.io/cgi-bin/logoutUser.cgi',myData, function(result) {
    if(result == "0"){
     console.log("failed");
   }
   else if(result == "1"){
     console.log("invalid input");
   }
   else{
     console.log("logged out");
     location.reload(true);
   }
  });
}
function escapeRegExp(string){
  return string.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); // $& means the whole matched string
}