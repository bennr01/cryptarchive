"""tool for reconstructing a cryptarchive index."""
import sys
import json
import re
import os

from cryptarchive.index import Index


def find_all_ids(s):
    """find all ids in s."""
    q = r'\"id\": ?\"[0-f]+'
    # q = r'\"id\": ?\"[a-zA-Z0-9/_\- \(\)]+'
    matches = re.findall(q, s)
    result = []
    for m in matches:
        result.append(m[m.rfind('"') + 1:])
    return result


def get_entry_for_id(s, id):
    """find the entry for id"""
    si = ei = s.rfind(id)

    # find dict subsection
    while s[si] != "{":
        si -= 1
    while s[ei] != "}":
        ei += 1
        if ei >= len(s):
            s += "}"
    m = s[si:ei+1]

    # find key
    ki = si
    kc = 0
    while True:
        if s[ki] == '"':
            kc += 1
            if kc == 2:
                break
        ki -= 1
    key = s[ki:si]
    key = key[:key.rfind(":")]
    key = key[1:-1]

    try:
        loaded = json.loads(m)
    except:
        print m
        return None
    else:
        return (key, loaded)


def reconstruct_pathlist(keys):
    """reconstruct the path list from the keys."""
    paths = []
    for key in keys:
        if key in paths:
            continue
        segments = key.split("/")[:-1]
        prev = []
        for i in range(len(segments)):
            seg = segments[i]
            p = "/".join(prev + [seg])
            if p not in paths:
                paths.append(p)
            prev.append(seg)
    return paths


def reconstruct(s, filelist=[], verbose=False):
    """
    Attemp to reconstruct the index.
    :param s: decrypted content of the old index
    :type s: str
    :param filelist: list of existing files in user directory
    :type filelist: list of str
    :param verbose: enable more output
    :type verbose: bool
    """
    # attemp to load index first
    if verbose:
        print "Loading index... ",
    try:
        index = Index.loads(s)
    except Exception as e:
        if verbose:
            print "Error: {e}\nBeginning recovery...".format(e=repr(e))
    else:
        if verbose:
            print "Done.\nThe index appears to be working, skipping reconstruction.",
        return index

    # find ids
    if verbose:
        print "Searching for IDs... ",
    ids = find_all_ids(s)
    if verbose:
        print "{n} found.".format(n=len(ids))

    # load entries and keys
    if verbose:
        print "Reading index entries for IDs... ",
    entries, keys = [], []
    for id in ids:
        key, entry = get_entry_for_id(s, id)
        keys.append(key)
        entries.append(entry)
    if verbose:
        print "{n} read.".format(n=len(entries))

    # reconstruct path list
    if verbose:
        print "Searching for hints of paths... "
    paths = reconstruct_pathlist(keys)
    if verbose:
        print "{n} found.".format(n=len(paths))

    # begin reconstruction
    if verbose:
        print "Recovery complete, beginning reconstruction..."
    index = Index.new()

    if verbose:
        print "Recreating paths... ",
    sorted_paths = [e[1] for e in sorted([(len(t), t) for t in paths])]
    for p in sorted_paths:
        index.mkdir(p)
    if verbose:
        print "{n} added.".format(n=len(sorted_paths))

    if verbose:
        print "Readding known files... ",
    added = []
    for k in keys:
        nfid = index.create_file(k)
        if nfid not in ids:
            raise Exception("It seems like the ID generation was changed; reconstruction is not possible :(")
        added.append(nfid)
    if verbose:
        print "{n} added.".format(n=len(added))

    if verbose:
        print "Adding unknown files...",
    skipped = []
    for fid in filelist:
        if fid in added:
            skipped.append(fid)
            continue
        else:
            index._index["dirs"]["/"]["/"+fid] = {
                "name": fid,
                "isdir": False,
                "id": fid,
                }
    if verbose:
        print "{n} added, {s} skipped.".format(n=len(filelist)-len(skipped), s=len(skipped))

    # end
    if verbose:
        print "Done."
        print "Data loss summary below:"
        filenameloss = ((len(filelist)-len(skipped)) / (len(filelist) + len(added)))* 100
        print "filenames: {p}% lost.".format(p=(filenameloss))
    return index


if __name__ == "__main__":
    reconstruct(open(sys.argv[1], "rb").read(), verbose=True)
