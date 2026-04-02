const container = document.getElementById("roadmap-container")

async function callBackend() {

const container = document.getElementById("roadmap-container")

container.innerHTML = "<p>Loading...</p>"

try {

const res = await fetch("http://127.0.0.1:8000/")
const data = await res.json()

container.innerHTML = ""

const card = document.createElement("div")
card.className = "card"

card.innerHTML = `
<h3>Backend Connected ✅</h3>
<p>${data.message}</p>
`

container.appendChild(card)

} catch (error) {

container.innerHTML = `
<div class="card">
<h3 style="color:red;">Error ❌</h3>
<p>${error}</p>
</div>
`

}

}

container.innerHTML=""

data.forEach(roadmap=>{

const card=document.createElement("div")
card.className="card"

card.innerHTML=`
<div class="tag">${roadmap.category}</div>
<h3>${roadmap.title}</h3>
<p>${roadmap.description}</p>
`

container.appendChild(card)

})

/* MODAL */

function openModal(){
document.getElementById("modal").style.display="flex"
}

function closeModal(){
document.getElementById("modal").style.display="none"
}

/* ADD ROADMAP */

function addRoadmap(){

const name=document.getElementById("name").value
const title=document.getElementById("title").value
const desc=document.getElementById("description").value
const category=document.getElementById("category").value

const card=document.createElement("div")

card.className="card"

card.innerHTML=`
<div class="tag">${category}</div>
<h3>${title}</h3>
<p>${desc}</p>
<small>Submitted by ${name}</small>
`

container.appendChild(card)

closeModal()

}

