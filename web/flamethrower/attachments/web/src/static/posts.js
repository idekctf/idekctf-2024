main = async () => {
  postId = new URLSearchParams(location.search).get('id') || "1";
  if (postId.slice(-1) === '/'){
    postId = postId.substring(0, postId.length - 1);
  };

  postContainer = document.getElementById('post-content');

  if (!isNaN(postId)){
    data = await (await fetch(`/api/post/${postId}`)).json();
    content = data['content'] || data['error'];
  } else {
    content = 'post not found :(';
  };

  postContainer.innerHTML = postContainer.innerHTML.replace('Content loading...', content);
};

main();
