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
	chat.innerHTML = `<hr class="divider" /><div class="message"><div class="username">${encryption} ${sender}<span class="timestamp">${time}</span></div><div class="content">${msg}</div></div>` + chat.innerHTML;
	if (current_rowid != 1){
		chat.innerHTML = `<button onclick="msg_load()" id="button">Load msg</button>` + chat.innerHTML;
	}
	update_scroll();
}

function add_msg_start(time, msg, sender, encryption, receiver_key){
	if (receiver_key != chat_key){
		alert("msg nie do tochto chatu");
		return;
	}
	var chat = document.getElementsByClassName("chat")[0];
	chat.innerHTML += `<hr class="divider" /><div class="message"><div class="username">${encryption} ${sender}<span class="timestamp">${time}</span></div><div class="content">${msg}</div></div>`;
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

eel.expose(add_msg_end);
eel.expose(add_msg_start);
eel.expose(add_key);
eel.expose(insert_exported_key);
eel.expose(update_scroll);
eel.expose(insert_mining_log);
eel.expose(edit_mining);
eel.expose(insert_name);
