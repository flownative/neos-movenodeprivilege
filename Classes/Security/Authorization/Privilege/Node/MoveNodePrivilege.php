<?php
namespace Flownative\Neos\MoveNodePrivilege\Security\Authorization\Privilege\Node;

/*
 * This file is part of the Flownative.Neos.MoveNodePrivilege package.
 *
 * (c) Karsten Dambekalns, Flownative GmbH
 *
 * This package is Open Source Software. For the full copyright and license
 * information, please view the LICENSE file which was distributed with this
 * source code.
 */

use Neos\ContentRepository\Domain\Model\NodeInterface;
use Neos\ContentRepository\Security\Authorization\Privilege\Node\AbstractNodePrivilege;
use Neos\ContentRepository\Security\Authorization\Privilege\Node\NodePrivilegeSubject;
use Neos\Flow\Security\Authorization\Privilege\Method\MethodPrivilegeSubject;
use Neos\Flow\Security\Authorization\Privilege\PrivilegeSubjectInterface;
use Neos\Flow\Security\Exception\InvalidPrivilegeTypeException;

/**
 * A privilege to restrict moving of nodes
 */
class MoveNodePrivilege extends AbstractNodePrivilege
{
    /**
     * @param PrivilegeSubjectInterface|NodePrivilegeSubject|MethodPrivilegeSubject $subject
     * @return boolean
     * @throws InvalidPrivilegeTypeException
     * @throws \Neos\Flow\Security\Exception
     */
    public function matchesSubject(PrivilegeSubjectInterface $subject)
    {
        if (!$subject instanceof NodePrivilegeSubject && !$subject instanceof MethodPrivilegeSubject) {
            throw new InvalidPrivilegeTypeException(sprintf('Privileges of type "%s" only support subjects of type "%s" or "%s", but we got a subject of type: "%s".', MoveNodePrivilege::class, NodePrivilegeSubject::class, MethodPrivilegeSubject::class, get_class($subject)), 1536253193);
        }

        if ($subject instanceof MethodPrivilegeSubject === true) {
            $this->initializeMethodPrivilege();
            if ($this->methodPrivilege->matchesSubject($subject) === false) {
                return false;
            }

            /** @var NodeInterface $node */
            $node = $subject->getJoinPoint()->getProxy();
            $nodePrivilegeSubject = new NodePrivilegeSubject($node);

            return parent::matchesSubject($nodePrivilegeSubject);
        }

        return parent::matchesSubject($subject);
    }

    /**
     * This is the pointcut expression for all methods to intercept. It targets all public methods that could move a node.
     *
     * @return string
     */
    protected function buildMethodPrivilegeMatcher()
    {
        return 'within(' . NodeInterface::class . ') && method(public .*->move.*())';
    }
}
