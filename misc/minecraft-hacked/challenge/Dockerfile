FROM gradle:jdk17

WORKDIR /app

COPY build.gradle settings.gradle gradlew gradle.properties .
COPY gradle gradle
RUN ./gradlew build
COPY . .

RUN ./gradlew runServer
RUN sed -i -e "s/false/true/g" run/eula.txt
RUN sed -i -e "s/online-mode=true/online-mode=false/g" run/server.properties
RUN sed -i -e "s/spawn-protection=16/spawn-protection=0/g" run/server.properties
RUN sed -i -e "s/motd=A Minecraft Server/motd=idekCTF - Minecraft:HACKED/g" run/server.properties
RUN sed -i -e "s/25565/1337/g" run/server.properties

RUN tar xf world.tar.gz -C run/

ENV FLAG=idekCTF{storage_tech_is_my_passion_c1bdf8b2}

CMD [ "./gradlew", "runServer" ]