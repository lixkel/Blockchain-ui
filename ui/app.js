var chat_key = "";

function init_load(){
	const urlParams = new URLSearchParams(window.location.search);
	chat_key = urlParams.get('key');
	eel.get_name(chat_key);
	eel.request_msg(chat_key, current_rowid);
}

function msg_load(){
	eel.request_msg(chat_key, current_rowid);
}

function input_get(){
	var input = document.getElementById("chat_input");
	var msg = input.value;
	if (msg == ""){
		return;
	}
	input.value = "";
	var encryption = document.getElementById("chat_checkbox").checked;
	eel.send_msg(msg, chat_key, encryption);
}

function add_msg_end(time, msg, sender, encryption, rowid){
	current_rowid = rowid;
	var button = document.getElementById("button");
	button.remove();
	var chat = document.getElementsByClassName("chat")[0];
	var icon;
	if(encryption){
		icon = `<img src="icons/locked.png">`;
	}
	else{
		icon = `<img src="icons/unlocked.png">`;
	}
	chat.innerHTML = `<hr class="divider" /><div class="message"><div class="username">${icon} ${sender}<span class="timestamp">${time}</span></div><div class="content">${msg}</div></div>` + chat.innerHTML;
	if (current_rowid != 1){
		chat.innerHTML = `<button class="button_message" onclick="msg_load()" id="button">Load msg</button>` + chat.innerHTML;
	}
}

function add_msg_start(time, msg, sender, encryption, receiver_key){
	if (receiver_key != chat_key){
		warning(`Nová správa od ${sender}`);
		return;
	}
	if(encryption){
		icon = `<img src="icons/locked.png">`;
	}
	else{
		icon = `<img src="icons/unlocked.png">`;
	}
	var chat = document.getElementsByClassName("chat")[0];
	chat.innerHTML += `<hr class="divider" /><div class="message"><div class="username">${icon} ${sender}<span class="timestamp">${time}</span></div><div class="content">${msg}</div></div>`;
	update_scroll();
}

function add_key(time, msg, sender, key, name){
	var user_list = document.getElementsByClassName("people")[0].getElementsByTagName("ul")[0];
	user_list.innerHTML = `<li><a href="chat.html?key=${key}">${name}<span class="little">${time}</span><div class="little">${msg}</div></a></li>` + user_list.innerHTML;
}

function import_key(){
	var key_input = document.getElementById("key_input");
	var name_input = document.getElementById("name_input");
	var new_key = key_input.value;
	var new_name = name_input.value;
	key_input.value = "";
	name_input.value = "";
	eel.import_key(new_key, new_name);
}

function insert_exported_key(key){
	var export_key = document.getElementsByClassName("export")[0];
	export_key.innerHTML = key;
}

function insert_mining_log(entry){
	if (location.href.split("/").slice(-1) != "mining.html"){
		return;
	}
	var log = document.getElementsByClassName("log")[0];
	log.innerHTML += entry;
}

function edit_mining(label){
	var button = document.getElementById("mining");
	button.innerHTML = label;
}

function update_scroll(){
  var chat = document.getElementById("chat");
  chat.scrollIntoView(false);
}

function insert_name(name){
  var head = document.getElementsByClassName("head")[0];
  head.innerHTML = name + head.innerHTML;
}

function edit(){
  var new_name = window.prompt("Zadaj nové meno pre tohto použivatela","Martin...");
	eel.edit(chat_key, new_name);
}

function new_alert(text){
  var body = document.getElementsByTagName("BODY")[0];
	body.innerHTML += `<div class="alert">${text}</div>`;
}

function rm_alert(){
	var al = document.getElementsByClassName("alert")[0];
	al.remove();
}

function rm_all_alerts(){
	var matches = document.getElementsByClassName("alert");
	for (var i = matches.length - 1; i >= 0; --i) {
  	matches[i].remove();
	}
}

function warning(msg){
	var body = document.getElementsByTagName("BODY")[0];
	body.innerHTML += `<div class="warning"><span class="closebtn" onclick="this.parentElement.remove();">&times;</span>${msg}</div>`;
}

function check_key(ele){
	if(event.keyCode === 13) {
		input_get();
	}
}

eel.expose(add_msg_end);
eel.expose(add_msg_start);
eel.expose(add_key);
eel.expose(insert_exported_key);
eel.expose(update_scroll);
eel.expose(insert_mining_log);
eel.expose(edit_mining);
eel.expose(insert_name);
eel.expose(new_alert);
eel.expose(rm_alert);
eel.expose(rm_all_alerts);
eel.expose(warning);
