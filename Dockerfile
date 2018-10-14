# Dockerfile for a cryptarchive server
# data will be stored to /data/
FROM pypy:2
RUN pip install -U cryptarchive
EXPOSE 45654
CMD cryptarchive-server --verbose -i 0.0.0.0 /data/

