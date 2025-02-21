# How to implement slug ? 
1) npm i slugify
2) Keep a slug field in your schema
3) Import slugify in your controller
4) slug: slugify(req.body.title) // pass it in your add product area