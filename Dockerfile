FROM python:3.11

RUN apt-get update && apt-get install -y --no-install-recommends \
        git \
 && rm -rf /var/lib/apt/lists/*

# Same path inside and outside so conda env scripts (which embed absolute
# paths) work either way.
WORKDIR /mnt/data/ngoctanbui/vul4py/vul4py_v2
