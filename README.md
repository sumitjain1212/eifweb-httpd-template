### EIF Apache config "git" repository.

This template is designed for 2.4 httpd shared hosting only.

### Cloning the main/remote repository to local path

    - On the remote server say "{{ GIT_REPO_NAME }}" as user `eifadmin`
    - On appropriate directory like
        - cd /opt/eif/web/httpd/httpd-*/conf.eifweb
    - Clone the reportiory like
        - git clone {{ GIT_REPO_URL }}
    - A directory "{{ GIT_REPO_NAME }}" get created with the latest apache config

###  To make changes to locally cloned repo

    - Edit files at will and then to add & commit run this
        - Go to base directory of the local repo
            - cd /opt/eif/web/httpd/httpd-*/conf.eifweb/{{ GIT_REPO_NAME }}
        - Add any/all files newly added
            -  git add -A ;
        - Commit changes to local repo
            - git commit -m "add your own commit comment" -a
        - Push the changes to main repo
            - git push origin master

     - To fetch latest changes from the main/remote repo
            - git pull

### To merge in latest updates from eifweb-httpd-template

```
# add remote
git remote add eifweb-httpd-template ssh://git@eifadmin-git.cisco.com:7999/eifadmin/eifweb-httpd-template.git
git remote -v

# fetch template
git fetch eifweb-httpd-template
git branch -a -vvv

# checkout & fetch the branch httpd-2.4
git checkout --track eifweb-httpd-template/httpd-2.4
git pull
git checkout master
```

Once remote is added you pull and merge
```
# pull latest httpd-2.4
git checkout httpd-2.4 && git pull && git checkout master

# check whats diff
git diff httpd-2.4

# merge stuff to master
git merge httpd-2.4

# push master
git push
```
