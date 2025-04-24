document.addEventListener("DOMContentLoaded", () => {
  const socket = io();
  const form = document.getElementById("chat-form");
  const input = document.getElementById("message-input");
  const box = document.getElementById("chat-box");

  form.addEventListener("submit", (e) => {
    e.preventDefault();
    const msg = input.value;
    if (msg.trim()) {
      // 메시지를 딕셔너리 형태로 전송
      socket.emit("message", {
        room_id: "global",  // 전체 채팅방 구분자 (필요 시 고정)
        content: msg
      });
      input.value = "";
    }
  });

  socket.on("message", (data) => {
    const p = document.createElement("p");
    p.classList.add("text-sm", "text-gray-700", "mb-1");

    // 서버에서 content만 보낼 수도 있고, 객체 전체 보낼 수도 있음
    p.textContent = typeof data === "string" ? data : data.content;
    box.appendChild(p);
    box.scrollTop = box.scrollHeight;
  });
});
