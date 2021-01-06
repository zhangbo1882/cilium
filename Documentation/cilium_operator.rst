.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

Cilium Operator
===============

.. note:: This document provides a technical overview of the Cilium
          operator and describes the cluster-wide operations it is
          responsible for.

Highly Available Cilium Operator
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The Cilium operator uses Kubernetes leader election library in conjunction with
lease locks to provide a HA cluster of cilium-operator instances. The
capability is supported on Kubernetes versions 1.14 and above and is
Cilium's default behavior since the 1.9 release.

The number of replicas for the HA deployment can be configured using
Helm option ``operator.replicas``.

.. parsed-literal::

    helm install cilium |CHART_RELEASE| \\
      --namespace kube-system \\
      --set operator.replicas=3

.. code:: bash

    $ kubectl get deployment cilium-operator -n kube-system
    NAME              READY   UP-TO-DATE   AVAILABLE   AGE
    cilium-operator   3/3     3            3           46s

The operator is an integral part of Cilium installations in Kubernetes
environments and is tasked to perform the following operations:

CRD Registration
~~~~~~~~~~~~~~~~

The default behavior of cilium-operator is to register the CRDs used by
Cilium. The following custom resources are registered by cilium-operator:

-  CiliumNetworkPolicy
-  CiliumClusterwideNetworkPolicy
-  CiliumEndpoint
-  CiliumNode
-  CiliumExternalWorkload
-  CiliumIdentity
-  CiliumLocalRedirectPolicy

IPAM
~~~~

Cilium-Operator is responsible for IP address management when running in
the following modes:

-  :ref:`ipam_azure`
-  :ref:`ipam_eni`
-  :ref:`ipam_crd_cluster_pool`

When running in IPAM mode :ref:`k8s_hostscope` the allocation CIDRs used by
``cilium-agent`` is derived from the fields ``podCIDR`` and ``podCIDRs``
populated by Kubernetes in the Kubernetes ``Node`` resource.

For :ref:`concepts_ipam_crd` IPAM allocation mode, it is the job of custom
operator, such as: "cilium-operator-aws", "cilium-operator-azure" to populate
the required information about CIDRs in the ``CiliumNode`` resource.

For more information on IPAM visit :ref:`address_management`.

KVStore operations
~~~~~~~~~~~~~~~~~~

These operations are performed only when KVStore is enabled for the
operator. In addition KVStore operations are only required when
``cilium-operator`` is running with any of the below options:

-  ``--synchronize-k8s-services``
-  ``--synchronize-k8s-nodes``
-  ``--identity-allocation-mode=kvstore``

K8s Services synchronization
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Cilium operator performs the job of synchronizing Kubernetes services to
external KVstore configured for the operator if running with
``--synchronize-k8s-services`` flag.

The operator performs this operation only for shared services(services
that have ``io.cilium/shared-service`` annotation set to true). This is
meaningful when running Cilium to setup a clustermesh.

K8s Nodes synchronization
^^^^^^^^^^^^^^^^^^^^^^^^^

Similar to K8s services, Cilium Operator also synchronize Kubernetes nodes
information to the shared KVstore.

When a ``Node`` object is deleted it is not possible to reliably cleanup
the corresponding ``CiliumNode`` object from the agent itself. The operator
holds the responsibility to garbage collect orphaned ``CiliumNodes``.

CNP/CCNP node status GC
^^^^^^^^^^^^^^^^^^^^^^^

Similar to the effect of ``Node`` object deletion on ``CiliumNode``,
Cilium Operator cannot remove the status corresponding to a node in a
CNP/CCNP object. This operation of node status garbage collection from
CNP/CCNP objects is also performed from the operator instead of the
``cilium-agent``.

This behavior can be disabled passing ``--set enableCnpStatusUpdates=false``
to ``helm install`` when installing or updating Cilium:

.. parsed-literal::

    helm install cilium |CHART_RELEASE| \\
      --namespace kube-system \\
      --set enableCnpStatusUpdates=false

Heartbeat update
^^^^^^^^^^^^^^^^

The operator periodically updates the Cilium's heartbeat path key
with the current time. The default key for this heartbeat is
``cilium/.heartbeat`` in the KVStore. It is used by agents to validate
that kvstore updates can be received.

Policy status update
^^^^^^^^^^^^^^^^^^^^

Cilium operator performs the operation of CNP/CCNP node status updates
when ``k8s-events-handover`` is enabled. This is done to optimize
Kubernetes events handling in case of large clusters. For the node
status updates to be handled by ``cilium-operator``, all the K8s events
are mirrored to the KVstore, which are then used to perform operations
via the operator. This operation is performed for both
CiliumNetworkPolicy and CiliumClusterwideNetworkPolicy objects.

For each CNP/CCNP object in the cluster, we start a status handler. This
handler periodically updates the node statuses for the CNP/CCNP objects
with the status of the policy in the corresponding node.

Identity Garbage Collection
~~~~~~~~~~~~~~~~~~~~~~~~~~~

Each workload in Kubernetes is assigned a security identity that is used
for policy decision making. This identity is based on common workload
markers like labels. Cilium supports two identity allocation mechanisms:

-  CRD Identity allocation
-  KVStore Identity allocation

Both the mechanisms of identity allocation requires the
``cilium-operator`` to perform the Garbage collection of stale
identities. This garbage collection is necessary because a 16-bit
unsigned integer represents the security identity, and thus we can only
have a maximum of 65536 identities in the cluster.

CRD Identity GC
^^^^^^^^^^^^^^^

CRD identity allocation uses Kubernetes custom resource
``CiliumIdentity`` to represent a security identity. This is the default
behaviour of Cilium and works out of the box in any K8s environment
without any external dependency.

The cilium operator maintains a local cache for CiliumIdentities with
the last time they were seen active. A controller runs in the background
periodically which scans this local cache and deletes identities that
have not had their heartbeat life sign updated since
``identity-heartbeat-timeout``.

One thing to note here is that an Identity is always assumed to be live
if it has an endpoint associated with it.

KVStore Identity GC
^^^^^^^^^^^^^^^^^^^

While the CRD allocation mode for identities is more common, it is
limited in terms of scale. When running in a very large environment, the
more sane choice is to use the KVStore allocation mode. This mode stores
the identities in an external store like etcd or Consul.

For more information on Cilium's scalability visit :ref:`scalability_guide`.

The garbage collection mechanism involves scanning the KVStore of all
the identities using prefix(``id/``) search for identity keys. For
each identity, we search in the KVstore if there are any users of that
ID. The entry is deleted from the store if there are no active users.

CiliumEndpoint garbage collection
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

CiliumEndpoint object is created by the Cilium agent for each Pod in the
cluster. The operator manages a controller to handle the garbage
collection of orphaned CiliumEndpoint objects. This controller is run
periodically if the ``endpoint-gc-interval`` option is specified and
only once during startup if the option is unspecified.

Derivative network policy creation
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

When using Cloud provider specific constructs like ``toGroups`` in the
network policy spec, the operator performs the job of converting these
constructs to derivative CNP/CCNP objects without these fields.

For more information, see how Cilium network policies incorporate the
use of ``toGroups`` to :ref:`lock down external access using AWS security groups<aws_metadata_with_policy>`.