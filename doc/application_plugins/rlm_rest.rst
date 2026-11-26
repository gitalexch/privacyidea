:orphan:

.. _rlm_rest:

Configuration of rlm_rest
=========================

FreeRADIUS 3 is shipped with the ``rlm_rest`` module, which can be used to transform
RADIUS authentication requests to HTTP requests to a suitable REST endpoint.
privacyIDEA implements such an endpoint (``/validate/radiuscheck``, see :ref:`rest_validate`).
The default response format supports authentication using HTTP status codes.
The optional :ref:`rlm_rest_push` format also supports PUSH challenge-response.
For general challenge-response and attribute mapping, see :ref:`rlm_perl`.

On Debian and Ubuntu, the required packages can be installed as follows::

    apt-get install freeradius freeradius-rest

On Debian and Ubuntu, the FreeRADIUS configuration is located in ``/etc/freeradius/3.0/``. Other distributions
may use a different directory, e.g. ``/etc/raddb/``.


Setup
-----

First, the ``rlm_rest`` module needs to be enabled::

    cd /etc/freeradius/3.0/mods-enabled
    ln -s ../mods-available/rest .


The authentication type needs to be configured in the ``/etc/freeradius/3.0/users`` file::

    DEFAULT Auth-Type := rest

and the site configuration should invoke the module as follows::

   authenticate {
        Auth-Type rest {
           rest
        }
        digest
        unix
   }

The module itself is then configured via the file ``/etc/freeradius/3.0/mods-enabled/rest``. First, ``connect_uri``
needs to point to your privacyIDEA instance::

    connect_uri = "https://127.0.0.1/"

The ``authenticate`` section needs to be modified as follows::

    authenticate {
        uri = "${..connect_uri}/validate/radiuscheck"
        method = 'post'
        body = 'post'
        data = "user=%{urlquote:%{User-Name}}&pass=%{urlquote:%{User-Password}}"
        force_to = 'plain'
        tls = ${..tls}
    }

Assuming ``clients.conf`` has been edited accordingly, the FreeRADIUS server should already respond
to authentication requests::

   echo "User-Name=user, User-Password=password" | radclient -sx yourRadiusServer \
      auth topsecret


For instructions on how to configure more advanced features of ``rlm_rest`` such as the connection pool or
TLS certificate validation, please consult the documentation in the configuration file.

.. _rlm_rest_push:

PUSH challenge-response without push_wait
-----------------------------------------

Use ``POST /validate/radiuscheck?response_format=freeradius`` with the
FreeRADIUS 3.2.x examples below to return an ``Access-Challenge`` while the
user confirms PUSH on their device. Each HTTP request returns without waiting
for the device. The default endpoint behavior remains empty HTTP 204 for success
and empty HTTP 400 for any other result.

Requirements
~~~~~~~~~~~~

* The NAS must support PAP and a sequence of ``Access-Request``,
  ``Access-Challenge``, and continuation ``Access-Request``. The continuation must
  preserve ``User-Name`` and ``State`` and include ``User-Password``. A nonempty
  placeholder such as ``continue`` is sufficient for standard PUSH because the
  device supplies the cryptographic answer.
* The user needs an enrolled PUSH token. Standard PUSH and
  ``push_require_presence`` are supported. For presence confirmation, the
  ``Reply-Message`` includes the choice to select on the device. Enrollment,
  ``push_code_to_phone``, other challenge token types, and mixed transactions
  containing other token types are outside this adapter's scope.
* Disable the ``push_wait`` policy for these requests. The adapter rejects a
  request with that policy enabled before triggering a PUSH.
* Keep TLS certificate and hostname verification enabled. Configure the trusted
  RADIUS clients and their shared secrets separately. The examples use a
  dedicated listener and IPv4 NAS packet source addresses.
* Use the same stable ``SECRET_KEY`` on all privacyIDEA workers serving these
  requests. State also binds the HTTP peer and effective client IP; proxy and
  load-balancer deployments must keep these addresses stable throughout an
  exchange. A key rotation invalidates outstanding States.

The NAS initiates every continuation. Device approval does not send an
unsolicited RADIUS reply. A NAS that cannot continue an Access-Challenge exchange
still needs a different integration or the existing ``push_wait`` flow.

FreeRADIUS configuration
~~~~~~~~~~~~~~~~~~~~~~~~

Create and enable a module instance named ``privacyidea_push`` using this file,
replacing the privacyIDEA hostname and configuring the CA trust for your site:

.. literalinclude:: examples/privacyidea_rest_push.conf
   :language: text

Create and enable the following dedicated virtual server. Its listener uses
port 18120; choose the address and port appropriate for your deployment. The
stock ``challenge`` policy in ``policy.d/control`` must be loaded.

.. literalinclude:: examples/privacyidea_rest_push_site.conf
   :language: text

``radius_nas`` is set from FreeRADIUS's packet source address, rather than the
NAS-Identifier supplied in the RADIUS packet. For IPv6 NAS clients use the
``Packet-Src-IPv6-Address`` attribute instead. If requests arrive through a
RADIUS proxy, this identifies that proxy; distinguishing downstream NAS devices
requires a trusted mapping in the RADIUS configuration.

The module calls include exactly ``User-Agent: FreeRADIUS``. Keep this client
identifier when adapting the example. Add required HTTP authorization headers
to ``REST-HTTP-Header`` without replacing User-Agent. If a realm or resolver is
sent explicitly, send the same values on every step.

The action override ``default = 1`` is essential. The authentication section's
default ``ok = return`` would otherwise allow an empty successful HTTP response
to finish authentication before the packet type is checked. The example accepts
only an explicit ``Access-Accept`` from a successful module call; errors,
missing attributes, and unknown response formats are rejected. Keep these
checks when merging the example into an existing virtual server.

Adjust the short HTTP timeout for the cost of creating the PUSH, including
gateway delivery. It does not need to cover the user's confirmation time.
Do not configure this endpoint with the legacy example's ``force_to = plain``.

API contract and lifecycle
~~~~~~~~~~~~~~~~~~~~~~~~~~

The request uses the usual ``user``, ``pass``, and optional ``realm`` and
``resolver`` parameters, plus:

.. list-table:: FreeRADIUS response format request parameters
   :header-rows: 1
   :widths: 25 75

   * - Parameter
     - Meaning
   * - ``response_format``
     - ``freeradius`` selects the adapter on ``/validate/radiuscheck`` only.
   * - ``radius_nas``
     - Required NAS binding, populated by the trusted FreeRADIUS configuration.
   * - ``state``
     - Empty or omitted initially; the exact State from Access-Challenge on continuation.

Pass the signed State, not a privacyIDEA transaction ID. Direct ``transaction_id``,
serial-only authentication, and enrollment parameters are rejected in this mode.
FreeRADIUS sends State as octets; the example converts the ASCII payload with
``%{string:State}`` before URL encoding it. The response encodes those octets
as a ``0x``-prefixed hexadecimal JSON value. A State is at most 166 octets,
below RADIUS's 253-octet limit.

.. list-table:: Response contract
   :header-rows: 1
   :widths: 15 25 60

   * - HTTP status
     - RADIUS packet type
     - JSON attributes
   * - 200
     - Access-Challenge
     - ``control:Response-Packet-Type``, ``reply:State``, ``reply:Reply-Message``
   * - 200
     - Access-Accept
     - ``control:Response-Packet-Type``
   * - 401
     - Access-Reject
     - ``control:Response-Packet-Type``

JSON values use rlm_rest's extended attribute syntax, for example::

    {"control:Response-Packet-Type": {
        "op": ":=", "value": "Access-Accept", "do_xlat": false
    }}

``do_xlat: false`` prevents reply text from being expanded as FreeRADIUS
expressions. Reply-Message is limited to 253 UTF-8 octets. Standard privacyIDEA
response signing may add a ``signature`` key; rlm_rest ignores unknown attributes.
The integration relies on verified HTTPS for the server identity.

The initial request checks the first factor and triggers PUSH using the existing
authentication path. State is signed and bound to the requested and resolved
user, realm/resolver, HTTP peer, effective client IP, and NAS binding.
Continuations also recheck ownership and the challenge's current validity.

An early continuation repeats Access-Challenge with the same State. It neither
creates another PUSH nor increases the token failcount or records a wrong-answer
authentication event for waiting. It does not extend the challenge's validity.
The normal pre-policies and authentication policies still apply.

After device approval, the continuation runs the normal authentication and
authorization path and consumes the approval once. An expired, declined,
cancelled, already-used, or invalid transaction cannot grant access. With several
PUSH tokens in the same transaction, an approved eligible token can complete the
exchange; an unanswered eligible token can keep it pending.

No call to ``/validate/polltransaction`` is needed. A readiness result would not
replace the final authentication. Authorization or conditional-access rejection,
and response policies that remove required challenge details, fail closed.
General RADIUS reply attribute mapping is not included.

Implementation references
~~~~~~~~~~~~~~~~~~~~~~~~~

The example targets the FreeRADIUS 3.2.x implementation:

* `rlm_rest module and HTTP status handling <https://github.com/FreeRADIUS/freeradius-server/blob/v3.2.x/src/modules/rlm_rest/rlm_rest.c>`_
* `JSON attribute decoder <https://github.com/FreeRADIUS/freeradius-server/blob/v3.2.x/src/modules/rlm_rest/rest.c>`_
* `REST configuration and custom headers <https://github.com/FreeRADIUS/freeradius-server/blob/v3.2.x/raddb/mods-available/rest>`_
* `Challenge policy <https://github.com/FreeRADIUS/freeradius-server/blob/v3.2.x/raddb/policy.d/control>`_
* `State conversion to a string <https://github.com/FreeRADIUS/freeradius-server/blob/v3.2.x/src/main/xlat.c>`_

This implementation, tests, and configuration examples were prepared with
assistance from OpenAI Codex. Consult the proposed PR's validation notes for the
checks actually run; source inspection does not replace testing with your NAS.
