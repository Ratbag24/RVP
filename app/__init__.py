"""Remote vulnerability assessment platform.

Step 1 scope: the database schema and the authorisation gate. Nothing in this
package sends a packet anywhere, by design - the gate is being built and proven
before any code that could touch a customer system exists.
"""
