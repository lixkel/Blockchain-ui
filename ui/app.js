function load(){
	const urlParams = new URLSearchParams(window.location.search);
	chat_key = urlParams.get('key');
	eel.request_msg(chat_key, current_rowid);
}

function input_get(){
	var input = document.getElementById("chat_input");
	var msg = input.value;
	if (msg == ""){
		return
	}
	input.value = "";
	var encryption = document.getElementById("chat_checkbox").checked;
	alert(encryption)
	eel.send_msg(msg, chat_key, encryption);
}

function add_msg_end(time, msg, sender, encryption, rowid){
	current_rowid = rowid;
	var chat = document.getElementsByClassName("chat")[0];
	chat.innerHTML = `<hr class="divider" /><div class="message"><div class="username">${encryption} ${sender}<span class="timestamp">${time}</span></div><div class="content">${msg}</div></div>` + chat.innerHTML;
}

function add_msg_start(time, msg, sender, encryption, receiver_key){
	if (receiver_key != chat_key){
		alert("msg nie do tochto chatu")
		return
	}
	var chat = document.getElementsByClassName("chat")[0];
	chat.innerHTML += `<hr class="divider" /><div class="message"><div class="username">${encryption} ${sender}<span class="timestamp">${time}</span></div><div class="content">${msg}</div></div>`;
}

function add_key(time, msg, sender, key, name){
	var user_list = document.getElementsByClassName("people")[0].getElementsByTagName("ul")[0];
	user_list.innerHTML = `<li><a href="chat.html?key=${key}">${name}<span class="little">${time}</span><div class="little">${msg}</div></a></li>` + user_list.innerHTML;
}


eel.expose(add_msg_end);
eel.expose(add_msg_start);
eel.expose(add_key);
