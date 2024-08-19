FROM julia:latest

RUN useradd -m ctf

WORKDIR /app

RUN chown ctf /app

USER ctf

COPY . . 

RUN julia -e 'using Pkg; Pkg.add("Genie")'

ENTRYPOINT ["julia", "app.jl"]
